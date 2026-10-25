"""Phase 2 adversarial tests of the broker's filesystem mailbox.

The attacker here is code running in a tenant sandbox (red, or the model worker) that can create, rename and
delete entries in the directories bind-mounted into it. Everything runs in temporary directories with synthetic
data and strict timeouts. A test that could block uses `bounded`, so a hang is reported as a failure, not a stall.
"""
import json
import os
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402

VICTIM_TEXT = "PHASE2-VICTIM-FILE-MUST-SURVIVE"


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


def bounded(fn, timeout=5.0):
    """Run fn in a thread; fail (instead of hanging the suite) if it does not finish."""
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - the caller decides what an exception means
            box["error"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "operation blocked for more than %.1f s" % timeout
    if "error" in box:
        raise box["error"]
    return box.get("value")


class Bench(runs.Broker):
    """Real Broker message handling and mailbox code; defence runner and model are in-process fakes and no
    container is started."""

    def __init__(self, run):
        super().__init__(run)
        self._mk_spool("red")
        self.names = {"red": "no-such-container"}
        self.calls = []

    def call(self, role, msg, timeout=15.0):
        self.calls.append((role, msg["op"]))
        if role == "blue":
            return {"ok": True, "verdict": "allow", "rule": None}
        return {"ok": True, "text": "Simulated safe response to: " + msg.get("prompt", "")[:20]}

    def start_workloads(self):
        pass

    def stop_workloads(self):
        pass


def make_bench(run_id="T-P2B", state="RUNNING"):
    runs.create_run(run_id, timing_bucket_ms=0)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state=state)
    return Bench(run)


@pytest.fixture
def bench():
    return make_bench()


def victim(tmp_path):
    v = tmp_path / "victim.txt"
    v.write_text(VICTIM_TEXT)
    return v


def commit(b, aid="A01", payload="hello world", nonce="n1"):
    b.dispatch("000001.json", {"op": "commit", "commitments": [{"attack_id": aid, "digest": commitment(nonce, payload)}]})
    return aid, payload, nonce


# ---------------------------------------------------------------- writes by the broker into tenant-writable directories
def test_P2B01_planted_symlink_at_temp_name_cannot_redirect_a_broker_write(bench, tmp_path):
    """The tenant knows the temp name of the next reply (.NAME.tmp) and links it to a file the broker can write."""
    v = victim(tmp_path)
    (bench.spool["red"] / "in" / ".000002.json.tmp").symlink_to(v)
    commit(bench)
    bench.handle("000002.json", {"op": "get_verdicts"})
    assert v.read_text() == VICTIM_TEXT, "broker followed a tenant-planted symlink and overwrote a file outside the mailbox"
    assert json.loads((bench.spool["red"] / "in" / "000002.json").read_text())["denied"] is True


def test_P2B02_relative_symlink_to_the_run_audit_log(bench):
    """Same attack with a relative link that resolves, on the host, to the run's own audit log."""
    audit = bench.run.dir / "audit.jsonl"
    before = audit.read_bytes()
    (bench.spool["red"] / "in" / ".000002.json.tmp").symlink_to("../../../audit.jsonl")
    bench.handle("000002.json", {"op": "get_verdicts"})
    assert audit.read_bytes().startswith(before), "the audit log was overwritten through a mailbox symlink"


def test_P2B03_fifo_at_temp_name_does_not_block_the_broker(bench):
    os.mkfifo(bench.spool["red"] / "in" / ".000002.json.tmp")
    bounded(lambda: bench.handle("000002.json", {"op": "get_verdicts"}), timeout=5)


def test_P2B04_directory_at_the_reply_name_does_not_fail_the_run(bench):
    d = bench.spool["red"] / "in" / "000002.json"
    d.mkdir()
    (d / "x").write_text("x")
    bounded(lambda: bench.handle("000002.json", {"op": "get_verdicts"}), timeout=5)
    assert bench.run.state == "RUNNING"


def test_P2B05_mailbox_directory_replaced_by_a_symlink_is_not_followed(bench, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    inbox = bench.spool["red"] / "in"
    os.rename(inbox, tmp_path / "moved-in")
    inbox.symlink_to(outside)
    try:
        bench.reply_red("000002.json", {"ok": True})
    except OSError:
        pass
    assert list(outside.iterdir()) == [], "broker wrote into a directory the tenant redirected it to"


def test_P2B06_hardlinked_or_preexisting_tmp_file_is_not_reused(bench, tmp_path):
    v = victim(tmp_path)
    os.link(v, bench.spool["red"] / "in" / ".000002.json.tmp")
    bench.handle("000002.json", {"op": "get_verdicts"})
    assert v.read_text() == VICTIM_TEXT, "broker wrote through a hard link planted at the temp name"


# ---------------------------------------------------------------- reads by the broker of tenant-written entries
@pytest.mark.parametrize("kind", ["fifo", "socket", "dir", "dir_with_content", "symlink_to_dir", "symlink_dangling", "empty",
                                  "bad_utf8", "truncated_json", "array", "scalar", "nul_bytes", "oversize", "huge_int",
                                  "deep_nesting"])
def test_P2B10_hostile_entries_in_out_are_rejected_without_blocking_and_removed(bench, tmp_path, kind):
    out = bench.spool["red"] / "out"
    p = out / "000001.json"
    if kind == "fifo":
        os.mkfifo(p)
    elif kind == "socket":
        s = socket.socket(socket.AF_UNIX)
        s.bind(str(p))
        s.close()
    elif kind == "dir":
        p.mkdir()
    elif kind == "dir_with_content":
        p.mkdir()
        (p / "a").write_text("a")
        (p / "sub").mkdir()
    elif kind == "symlink_to_dir":
        p.symlink_to(tmp_path)
    elif kind == "symlink_dangling":
        p.symlink_to(tmp_path / "nowhere")
    elif kind == "empty":
        p.write_bytes(b"")
    elif kind == "bad_utf8":
        p.write_bytes(b'{"op":"\xff\xfe\xfa"}')
    elif kind == "truncated_json":
        p.write_bytes(b'{"op":"attack","payload":"abc')
    elif kind == "array":
        p.write_text("[1,2,3]")
    elif kind == "scalar":
        p.write_text("42")
    elif kind == "nul_bytes":
        p.write_bytes(b'{"op":"x"}\x00\x00\x00')
    elif kind == "oversize":
        p.write_text(json.dumps({"op": "x", "pad": "a" * (runs.MAX_MSG + 5)}))
    elif kind == "huge_int":
        p.write_text('{"op":' + "9" * 20000 + "}")
    elif kind == "deep_nesting":
        p.write_text("[" * 50000)
    with pytest.raises((ValueError, OSError)):
        bounded(lambda: runs._safe_read(p), timeout=5)
    assert not os.path.lexists(p), "rejected entry was left in the mailbox (denial loop)"


# ---------------------------------------------------------------- message content that tries to break the broker
@pytest.mark.parametrize("msg", [
    {"op": "selfcheck", "checks": "not-a-list"},
    {"op": "selfcheck", "checks": [{"a": [[[[[]]]]]}]},
    {"op": "selfcheck", "checks": {"k": "v"}},
    {"op": "selfcheck", "checks": [float("nan"), float("inf")]},
    {"op": "selfcheck", "checks": ["\ud800"]},
    {"op": "commit", "commitments": "x"},
    {"op": "commit", "commitments": [1, 2, 3]},
    {"op": "commit", "commitments": [{"attack_id": "A"}]},
    {"op": "commit", "commitments": [{"attack_id": ["a"], "digest": {"d": 1}}]},
    {"op": "commit", "commitments": [{"attack_id": "\ud800", "digest": "x"}]},
    {"op": "attack", "attack_id": None, "payload": None, "nonce": None},
    {"op": "attack", "attack_id": "A01", "payload": 5, "nonce": [1]},
    {"op": "attack", "attack_id": "A01", "payload": "\ud800", "nonce": "n1"},
    {"op": "attack", "attack_id": "A" * 60000, "payload": "x", "nonce": "n"},
    {"op": "done", "observed": "x"},
    {"op": "done", "observed": [{"a": float("nan")}]},
    {"op": ["list"]},
    {"op": {"a": 1}},
    {"op": 5},
    {},
])
def test_P2B20_odd_but_valid_json_never_aborts_the_run(bench, msg):
    commit(bench)
    p = bench.spool["red"] / "out" / "000007.json"
    p.write_text(json.dumps(msg))
    try:
        parsed = runs._safe_read(p)
    except (ValueError, OSError):
        return
    bench.dispatch("000007.json", parsed)  # any exception type dispatch() does not convert would fail the whole run


def test_P2B21_deeply_nested_selfcheck_does_not_fail_the_run(bench):
    """Nesting just below the parser's limit passes json.loads but can exceed the recursion limit when the broker
    later hashes or writes it. Such a message must be a denial, not a failed run."""
    depth = 900
    payload = '{"op":"selfcheck","checks":' + "[" * depth + "]" * depth + "}"
    p = bench.spool["red"] / "out" / "000003.json"
    p.write_text(payload)
    try:
        msg = runs._safe_read(p)
    except (ValueError, OSError):
        return
    try:
        bench.dispatch("000003.json", msg)
    except RecursionError:
        pytest.fail("a nested JSON message raised RecursionError inside the broker (execute() would fail the run)")


# ---------------------------------------------------------------- whole broker loop against a hostile tenant
def run_loop(bench, driver, timeout=15):
    """Run Broker.execute() in a thread, with `driver` playing the red tenant. Returns the final run state."""
    import aegis.runs as rm
    orig_running, orig_stop = runtime.running, runtime.stop
    runtime.running = lambda name: True
    runtime.stop = lambda name: None
    try:
        t = threading.Thread(target=bench.execute, daemon=True)
        t.start()
        drv = threading.Thread(target=driver, daemon=True)
        drv.start()
        t.join(timeout)
        assert not t.is_alive(), "broker loop did not finish"
        drv.join(2)
    finally:
        runtime.running, runtime.stop = orig_running, orig_stop
    return bench.run.state


def tenant_send(bench, name, obj):
    out = bench.spool["red"] / "out"
    tmp = out / ("." + name + ".tmp")
    tmp.write_text(json.dumps(obj))
    os.rename(tmp, out / name)


def test_P2B30_hostile_stream_then_clean_finish_seals_the_run(bench):
    out = bench.spool["red"] / "out"

    def driver():
        os.mkfifo(out / "000001.json")
        (out / "000002.json").mkdir()
        os.symlink("/etc/passwd", out / "000003.json")
        (out / "000004.json").write_bytes(b"\xff\xfe")
        (out / "000005.json").write_text("[]")
        tenant_send(bench, "000006.json", {"op": "commit", "commitments": []})
        time.sleep(0.2)
        tenant_send(bench, "000007.json", {"op": "done", "observed": []})
    state = run_loop(bench, driver)
    assert state == "SEALED"
    assert not any(os.path.lexists(out / n) for n in ("000001.json", "000002.json", "000003.json", "000004.json", "000005.json"))
    denied = [e for e in read_jsonl(bench.run.dir / "audit.jsonl") if e["type"] == "policy.denied"]
    assert len(denied) == 5


def test_P2B31_directory_planted_at_a_future_reply_name_does_not_fail_the_run(bench):
    """The tenant pre-creates a non-empty directory where the broker will later put its reply."""
    inbox = bench.spool["red"] / "in"

    def driver():
        d = inbox / "000001.json"
        d.mkdir()
        (d / "keep").write_text("x")
        tenant_send(bench, "000001.json", {"op": "get_verdicts"})
        time.sleep(0.3)
        tenant_send(bench, "000002.json", {"op": "done", "observed": []})
    assert run_loop(bench, driver) == "SEALED"


def test_P2B32_fifo_planted_at_a_future_temp_name_does_not_stall_the_run(bench):
    inbox = bench.spool["red"] / "in"

    def driver():
        os.mkfifo(inbox / ".000001.json.tmp")
        tenant_send(bench, "000001.json", {"op": "get_verdicts"})
        time.sleep(0.3)
        tenant_send(bench, "000002.json", {"op": "done", "observed": []})
    assert run_loop(bench, driver, timeout=10) == "SEALED"


def test_P2B33_message_flood_is_bounded_in_audit_growth(bench):
    """A tenant that sends many rejected messages must not make the signed audit log grow without bound."""
    out = bench.spool["red"] / "out"
    n = 400

    def driver():
        for i in range(1, n + 1):
            tenant_send(bench, "%06d.json" % i, {"op": "get_verdicts"})
        time.sleep(0.5)
        tenant_send(bench, "%06d.json" % (n + 1), {"op": "done", "observed": []})
    run_loop(bench, driver, timeout=60)
    entries = read_jsonl(bench.run.dir / "audit.jsonl")
    denied = sum(e["type"] == "policy.denied" for e in entries)
    assert denied <= 150, "%d audit entries written for %d rejected messages" % (denied, n)


def test_P2B34_tenant_text_in_attack_id_does_not_reach_the_monitoring_stream(bench):
    marker = "RED-CHOSEN-ID-<script>-5531"
    aid, payload, nonce = commit(bench, aid=marker)
    bench.dispatch("000002.json", {"op": "attack", "attack_id": aid, "payload": payload, "nonce": nonce})
    assert marker not in (bench.run.dir / "monitor.jsonl").read_text(), \
        "a tenant-chosen identifier is copied verbatim into the observer-visible monitoring stream"


def test_P2B35_selfcheck_content_in_the_signed_audit_log_is_bounded(bench):
    """The self-check is the tenant's own report; it may be recorded but must be size- and type-bounded."""
    big = "SELFCHECK-TENANT-TEXT-9917" * 2000
    bench.handle("000001.json", {"op": "selfcheck", "checks": [{"check": big, "result": big, "extra": {"k": big}}] * 30})
    entries = [e for e in read_jsonl(bench.run.dir / "audit.jsonl") if e["type"] == "sandbox.selfcheck"]
    assert len(json.dumps(entries)) < 12000, "unbounded tenant text was written to the signed audit log"


# ---------------------------------------------------------------- identity, timeouts, shutdown
@pytest.mark.parametrize("op", ["inspect_input", "inspect_output", "generate", "attest", "stats", "shutdown", "selfcheck2", "SELFCHECK",
                                "attack ", "commit\x00", "done\n"])
def test_P2B40_operations_that_belong_to_other_workloads_are_denied_and_not_forwarded(bench, op):
    commit(bench)
    bench.calls.clear()
    bench.dispatch("000009.json", {"op": op, "text": "x", "prompt": "x"})
    r = json.loads((bench.spool["red"] / "in" / "000009.json").read_text())
    assert r.get("denied") is True and bench.calls == []


def test_P2B41_claimed_run_role_or_path_fields_never_change_what_the_broker_touches(tmp_path):
    a = make_bench("T-ID-A")
    runs.create_run("T-ID-B", timing_bucket_ms=0)
    other_before = {p.name: p.read_bytes() for p in store.run_dir("T-ID-B").rglob("*") if p.is_file()}
    payload = "hello world"
    msgs = [{"op": "commit", "run_id": "T-ID-B", "role": "operator", "tenant": "blue", "path": "../T-ID-B/sealed/canary.json",
             "commitments": [{"attack_id": "A01", "digest": commitment("n1", payload), "run_id": "T-ID-B", "path": "../../x"}]},
            {"op": "attack", "run_id": "T-ID-B", "spool": "../T-ID-B/spool/red", "attack_id": "A01", "payload": payload, "nonce": "n1"},
            {"op": "selfcheck", "run_id": "T-ID-B", "checks": [{"check": "../T-ID-B/run.json", "result": "x"}]}]
    for i, m in enumerate(msgs, start=1):
        a.dispatch("%06d.json" % i, m)
    other_after = {p.name: p.read_bytes() for p in store.run_dir("T-ID-B").rglob("*") if p.is_file()}
    assert other_after == other_before, "a message for run A changed files of run B"
    assert not any("T-ID-B" in l for l in (a.run.dir / "audit.jsonl").read_text().splitlines() if '"attack.evaluated"' in l)


def test_P2B42_unanswered_worker_times_out_quickly_and_the_run_fails_closed_with_cleanup(monkeypatch):
    b = make_bench("T-TMO")
    stopped = []
    monkeypatch.setattr(runtime, "stop", lambda n: stopped.append(n))
    monkeypatch.setattr(runtime, "running", lambda n: True)
    b.names = {"red": "r-x", "blue": "b-x", "model": "m-x"}
    b.start_workloads = lambda: (_ for _ in ()).throw(TimeoutError("blue did not answer"))
    t0 = time.monotonic()
    bounded(b.execute, timeout=10)
    assert time.monotonic() - t0 < 5
    assert b.run.state == "FAILED" and set(stopped) == {"r-x", "b-x", "m-x"}
    assert runs.verify_run("T-TMO")["ok"]


def test_P2B43_real_call_times_out_without_a_responder(bench):
    real_call = runs.Broker.call
    bench._mk_spool("blue")
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        real_call(bench, "blue", {"op": "attest"}, timeout=0.3)
    assert time.monotonic() - t0 < 2


def test_P2B44_messages_written_after_done_are_ignored_and_do_not_reach_the_log(bench):
    out = bench.spool["red"] / "out"

    def driver():
        tenant_send(bench, "000001.json", {"op": "done", "observed": []})
        for i in range(2, 30):  # keeps writing while the broker shuts down
            try:
                tenant_send(bench, "%06d.json" % i, {"op": "get_verdicts"})
            except OSError:
                break
    assert run_loop(bench, driver) == "SEALED"
    entries = read_jsonl(bench.run.dir / "audit.jsonl")
    assert entries[-1]["type"] == "run.sealed"
    assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
    assert runs.verify_run("T-P2B", tail_ok=True)["ok"]


def test_P2B45_rejected_entries_never_accumulate(bench):
    out = bench.spool["red"] / "out"
    for i in range(1, 200):
        (out / ("%06d.json" % i)).write_text("[")
    for n in runs._list_messages(out):
        with pytest.raises((ValueError, OSError)):
            runs._safe_read(out / n)
    assert os.listdir(out) == []


def test_P2B46_concurrent_checkpoints_from_separate_run_objects_get_unique_indexes():
    b = make_bench("T-CP")
    errors = []

    def go(k):
        try:
            for _ in range(10):
                runs.Run("T-CP").checkpoint("periodic")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    ts = [threading.Thread(target=go, args=(k,)) for k in range(6)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert not errors
    idx = [c["cp_seq"] for c in read_jsonl(store.vault_path("T-CP"))]
    assert idx == list(range(1, len(idx) + 1)), "duplicate or missing checkpoint index"


# ---------------------------------------------------------------- the model worker and defence runner are untrusted peers too
@pytest.mark.parametrize("reply", [{"text": 5}, {"text": None}, {"text": {"a": 1}}, {"text": ["x"]}, {}, {"ok": False},
                                   {"text": "x" * 60000}, {"text": "\ud800"}, {"text": "CANARY-aaaaaaaaaaaa [UNSAFE-MARKER]"}])
def test_P2B50_odd_model_replies_never_fail_the_run_or_leak_into_the_monitor(bench, reply):
    commit(bench)
    orig = bench.call
    bench.call = lambda role, msg, timeout=15.0: reply if role == "model" else orig(role, msg, timeout)
    bench.dispatch("000002.json", {"op": "attack", "attack_id": "A01", "payload": "hello world", "nonce": "n1"})
    assert bench.run.state == "RUNNING"
    mon = (bench.run.dir / "monitor.jsonl").read_text()
    assert "x" * 100 not in mon and "UNSAFE-MARKER" not in mon and "CANARY-aaaa" not in mon
    r = json.loads((bench.spool["red"] / "in" / "000002.json").read_text())
    assert "denied" in r or "output" in r


@pytest.mark.parametrize("verdict", [{"verdict": ["block"]}, {"verdict": 5}, {}, {"ok": True}, {"verdict": None}, {"verdict": "ALLOW"}, "allow"])
def test_P2B51_unclear_defence_verdicts_fail_closed(bench, verdict):
    commit(bench)
    orig = bench.call
    bench.call = lambda role, msg, timeout=15.0: verdict if role == "blue" else orig(role, msg, timeout)
    bench.dispatch("000002.json", {"op": "attack", "attack_id": "A01", "payload": "hello world", "nonce": "n1"})
    assert bench.run.state == "RUNNING"
    r = json.loads((bench.spool["red"] / "in" / "000002.json").read_text())
    assert r["refused"] is True and r["output"] == runs.UNIFORM_REFUSAL
    assert ("model", "generate") not in bench.calls


def test_P2B52_payload_and_model_output_markers_never_reach_the_monitoring_stream_or_the_signed_log(bench):
    marker = "SYNTHETIC-PAYLOAD-MARKER-P2-7730"
    out_marker = "SYNTHETIC-MODEL-OUTPUT-MARKER-P2-7731"
    commit(bench, aid="A01", payload=marker)
    orig = bench.call
    bench.call = lambda role, msg, timeout=15.0: ({"ok": True, "text": out_marker + " " + msg.get("prompt", "")} if role == "model" else orig(role, msg, timeout))
    bench.dispatch("000002.json", {"op": "attack", "attack_id": "A01", "payload": marker, "nonce": "n1"})
    for f in ("monitor.jsonl", "audit.jsonl", "checkpoints.jsonl", "run.json"):
        p = bench.run.dir / f
        if p.exists():
            assert marker not in p.read_text() and out_marker not in p.read_text(), f
    assert marker in (bench.run.dir / "sealed" / "artifacts.jsonl").read_text()  # kept only in the sealed store
