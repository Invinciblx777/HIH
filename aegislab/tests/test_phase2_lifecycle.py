"""Phase 2: lifecycle races, run isolation and result gating.

Races are forced with barriers and by pausing a thread at a chosen point, not left to chance. Stress loops have a fixed,
reported iteration count.
"""
import json
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, audit, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402

STRESS_ITERATIONS = 25


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for v in ("AEGIS_VAULT", "AEGIS_ANCHORS"):
        monkeypatch.delenv(v, raising=False)


def sealed_run(run_id, evaluated=3):
    runs.create_run(run_id, timing_bucket_ms=0)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state="RUNNING")
    for i in range(evaluated):
        run.log("attack.evaluated", "broker", {"attack_id": "A%02d" % i})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED")
    run.checkpoint("seal")
    return run


def in_threads(n, fn, *args):
    """Start n threads at a barrier and collect (result | exception) per thread."""
    barrier = threading.Barrier(n)
    out = [None] * n

    def go(i):
        barrier.wait(10)
        try:
            out[i] = ("ok", fn(i, *args))
        except BaseException as exc:  # noqa: BLE001
            out[i] = ("err", exc)
    ts = [threading.Thread(target=go, args=(i,), daemon=True) for i in range(n)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert not any(t.is_alive() for t in ts), "a thread did not finish (deadlock?)"
    return out


def assert_consistent_terminal(run_id, state):
    run = runs.Run(run_id)
    entries = read_jsonl(run.dir / "audit.jsonl")
    vault = read_jsonl(store.vault_path(run_id))
    assert run.state == state, run.state
    v = runs.verify_run(run_id)
    assert v["ok"], v["findings"]
    assert v["terminal_verified"] and v["terminal_state"] == state
    terminals = [c for c in vault if c.get("reason") == "terminal"]
    assert len(terminals) == 1 and vault[-1] is not None and vault[-1]["reason"] == "terminal"
    assert terminals[0]["seq"] == len(entries) == terminals[0]["event_count"] and terminals[0]["head"] == entries[-1]["hash"]
    assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
    assert sum(e["type"] in ("run.released", "run.failed") for e in entries) == 1


# ------------------------------------------------------------------ concurrent transitions
def test_P2L01_concurrent_release_has_exactly_one_winner():
    for i in range(STRESS_ITERATIONS):
        rid = "L1-%02d" % i
        sealed_run(rid)
        res = in_threads(6, lambda k: runs.release(rid, actor="reviewer"))
        wins = [r for r in res if r[0] == "ok"]
        assert len(wins) == 1, [repr(r[1]) for r in res if r[0] == "err"]
        assert all(isinstance(r[1], runs.GateError) for r in res if r[0] == "err"), [repr(r[1]) for r in res if r[0] == "err"]
        assert_consistent_terminal(rid, "RELEASED")


def test_P2L02_concurrent_start_launches_exactly_one_broker(monkeypatch):
    launched = []
    monkeypatch.setattr(runs.Broker, "execute", lambda self: launched.append(self.run.id))
    for i in range(STRESS_ITERATIONS):
        rid = "L2-%02d" % i
        runs.create_run(rid, timing_bucket_ms=0)
        runs.freeze(rid)
        res = in_threads(6, lambda k: runs.start(rid, wait=True))
        assert sum(r[0] == "ok" for r in res) == 1, [repr(r[1]) for r in res if r[0] == "err"]
    assert len(launched) == STRESS_ITERATIONS


def test_P2L03_concurrent_create_has_exactly_one_winner():
    for i in range(STRESS_ITERATIONS):
        rid = "L3-%02d" % i
        res = in_threads(6, lambda k: runs.create_run(rid, timing_bucket_ms=0))
        assert sum(r[0] == "ok" for r in res) == 1
        assert all(isinstance(r[1], runs.GateError) for r in res if r[0] == "err"), [repr(r[1]) for r in res if r[0] == "err"]
        entries = read_jsonl(store.run_dir(rid) / "audit.jsonl")
        assert [e["type"] for e in entries] == ["run.created"]


def test_P2L04_failed_creation_does_not_block_the_run_id(tmp_path):
    bad = tmp_path / "bad_pack.json"
    bad.write_text("{not json")
    with pytest.raises(Exception):
        runs.create_run("L4-A", attack_pack=bad)
    runs.create_run("L4-A", timing_bucket_ms=0)  # the id is free again


def test_P2L05_defence_config_update_racing_freeze_never_lands_after_the_freeze():
    """Either the update completes before the freeze (and is what gets frozen) or it is denied; an update must never be
    recorded after run.frozen, and the frozen config must equal the last accepted one."""
    for i in range(STRESS_ITERATIONS):
        rid = "L5-%02d" % i
        runs.create_run(rid, timing_bucket_ms=0)
        cfg = {"version": "race-%d" % i, "input_patterns": ["x"], "output_patterns": []}
        res = in_threads(2, lambda k: runs.freeze(rid) if k == 0 else runs.update_defence_config(rid, cfg, actor="blue_participant"))
        assert res[0][0] == "ok", res[0]
        entries = read_jsonl(store.run_dir(rid) / "audit.jsonl")
        types = [e["type"] for e in entries]
        frozen_at = types.index("run.frozen")
        assert "config.updated" not in types[frozen_at + 1:], types
        frozen = store.run_dir(rid) / "frozen/defence_config.json"
        working = store.run_dir(rid) / "blue_working_config.json"
        assert frozen.read_bytes() == working.read_bytes(), "working config changed after the freeze copy"
        assert not any(r[0] == "err" and not isinstance(r[1], runs.GateError) for r in res), res


def test_P2L06_state_updates_are_not_lost_under_concurrent_writers():
    runs.create_run("L6", timing_bucket_ms=0)
    run = runs.Run("L6")
    n = 8

    def bump(k):
        for j in range(20):
            runs.Run("L6").update(**{"w%d" % k: j})
    in_threads(n, bump)
    rec = run.record
    assert all(rec.get("w%d" % k) == 19 for k in range(n)), rec


# ------------------------------------------------------------------ release racing denied reads
def test_P2L10_denied_read_that_pauses_before_its_checkpoint_cannot_follow_the_terminal_checkpoint(monkeypatch):
    """Deterministic version of the dangerous interleaving: a denied read appends its entry while the run is SEALED, then is
    delayed; the release completes (final event, terminal checkpoint); only then does the reader write its post-seal
    checkpoint. That checkpoint must not end up after the terminal one."""
    sealed_run("L10")
    original = runs.Run.checkpoint
    reader_in_checkpoint, release_done = threading.Event(), threading.Event()

    def paused(self, reason):
        if threading.current_thread().name == "reader" and reason == "post-seal":
            reader_in_checkpoint.set()
            assert release_done.wait(15)
        return original(self, reason)
    monkeypatch.setattr(runs.Run, "checkpoint", paused)
    box = {}

    def reader():
        box["r"] = runs.Run("L10").log("policy.denied", "observer", {"op": "read_artifacts"})
    t = threading.Thread(target=reader, name="reader", daemon=True)
    t.start()
    assert reader_in_checkpoint.wait(10)
    runs.release("L10")
    release_done.set()
    t.join(15)
    assert not t.is_alive()
    assert_consistent_terminal("L10", "RELEASED")


def test_P2L11_denied_reads_racing_release_stress():
    for i in range(STRESS_ITERATIONS):
        rid = "L11-%02d" % i
        sealed_run(rid)

        def work(k):
            if k == 0:
                return runs.release(rid)
            for _ in range(8):
                runs.Run(rid).log("policy.denied", "observer", {"op": "read_artifacts"},
                                  monitor={"summary": "denied", "decision": "denied"})
        res = in_threads(6, work)
        assert res[0][0] == "ok", res[0]
        assert all(r[0] == "ok" for r in res[1:]), [repr(r[1]) for r in res if r[0] == "err"]
        assert_consistent_terminal(rid, "RELEASED")


def test_P2L12_events_after_release_never_enter_the_signed_chain():
    sealed_run("L12")
    runs.release("L12")
    before = (store.run_dir("L12") / "audit.jsonl").read_bytes()
    vault_before = store.vault_path("L12").read_bytes()
    for _ in range(10):
        runs.Run("L12").log("policy.denied", "observer", {"op": "read_artifacts"})
        runs.Run("L12").log("attack.evaluated", "broker", {"attack_id": "LATE"})
    assert (store.run_dir("L12") / "audit.jsonl").read_bytes() == before
    assert store.vault_path("L12").read_bytes() == vault_before
    assert_consistent_terminal("L12", "RELEASED")


def test_P2L13_release_is_not_repeatable_and_does_not_change_the_evidence():
    sealed_run("L13")
    runs.release("L13")
    snap = {p.name: p.read_bytes() for p in (store.run_dir("L13")).iterdir() if p.name in ("audit.jsonl", "checkpoints.jsonl")}
    for _ in range(3):
        with pytest.raises(runs.GateError):
            runs.release("L13")
    assert snap == {p.name: p.read_bytes() for p in (store.run_dir("L13")).iterdir() if p.name in snap}
    assert_consistent_terminal("L13", "RELEASED")


# ------------------------------------------------------------------ failures
def test_P2L20_exception_while_recording_an_event_fails_closed(monkeypatch):
    """The seal step raises; the broker's catch-all must still end the run in a verifiable FAILED state and never release."""
    runs.create_run("L20", timing_bucket_ms=0)
    runs.freeze("L20")
    run = runs.Run("L20")
    run.update(state="RUNNING")
    b = runs.Broker(run)
    b.start_workloads = lambda: None
    monkeypatch.setattr(runtime, "running", lambda n: False)
    monkeypatch.setattr(runtime, "stop", lambda n: None)
    b._mk_spool("red")
    b.names = {"red": "x"}
    orig = audit.AuditLog.append

    def boom(self, type_, actor, data, close=False):
        if type_ == "run.sealed":
            raise OSError("disk full (injected)")
        return orig(self, type_, actor, data, close=close)
    monkeypatch.setattr(audit.AuditLog, "append", boom)
    b.stop_workloads = lambda: None
    b.execute()
    assert_consistent_terminal("L20", "FAILED")
    with pytest.raises(runs.GateError):
        runs.release("L20")
    with pytest.raises(runs.GateError):
        runs.artifacts("L20")


def test_P2L21_failed_run_never_exposes_artifacts_through_the_api(monkeypatch):
    runs.create_run("L21", timing_bucket_ms=0)
    runs.freeze("L21")
    run = runs.Run("L21")
    run.update(state="RUNNING")
    store.append_jsonl(run.dir / "sealed/artifacts.jsonl", {"attack_id": "A01", "payload": "SYNTHETIC-L21-PAYLOAD"})
    run.log("run.failed", "control-plane", {"error": "X"}, checkpoint=False, close=True)
    run.update(state="FAILED")
    run.terminal_checkpoint("FAILED")
    c = TestClient(api.app, raise_server_exceptions=False)
    toks = store.tokens()
    for role in ("reviewer", "operator", "blue_participant", "red_participant"):
        r = c.get("/api/runs/L21/artifacts", headers={"X-Aegis-Token": toks[role]})
        assert r.status_code == 403 and "SYNTHETIC-L21-PAYLOAD" not in r.text
    assert c.post("/api/runs/L21/release", headers={"X-Aegis-Token": toks["reviewer"]}).status_code == 409


def test_P2L22_worker_failure_mid_run_ends_failed_and_verifies(monkeypatch):
    runs.create_run("L22", timing_bucket_ms=0)
    runs.freeze("L22")
    run = runs.Run("L22")
    run.update(state="RUNNING")
    b = runs.Broker(run)

    def explode():
        raise runs.GateError("worker died (injected)")
    b.start_workloads = explode
    monkeypatch.setattr(runtime, "stop", lambda n: None)
    b.execute()
    assert_consistent_terminal("L22", "FAILED")


def test_P2L23_failure_path_racing_a_release_attempt_stays_consistent(monkeypatch):
    """A run that is SEALED when a late failure and a release arrive together must end in exactly one terminal state."""
    for i in range(STRESS_ITERATIONS):
        rid = "L23-%02d" % i
        sealed_run(rid)
        monkeypatch.setattr(runtime, "stop", lambda n: None)

        def fail():
            run = runs.Run(rid)
            with run.lifecycle():
                if run.record.get("terminal") or run.audit.closed:
                    return "already terminal"
                run.log("run.failed", "control-plane", {"error": "late"}, checkpoint=False, close=True)
                run.update(state="FAILED")
                run.terminal_checkpoint("FAILED")
            return "failed"
        res = in_threads(2, lambda k: fail() if k == 0 else runs.release(rid))
        state = runs.Run(rid).state
        assert state in ("RELEASED", "FAILED")
        assert_consistent_terminal(rid, state)


# ------------------------------------------------------------------ availability: denial flood
def test_P2L30_anonymous_denial_flood_is_bounded_and_the_run_still_verifies():
    sealed_run("L30")
    c = TestClient(api.app, raise_server_exceptions=False)
    t0 = time.monotonic()
    for _ in range(600):
        assert c.get("/api/runs/L30/artifacts").status_code == 403
    elapsed = time.monotonic() - t0
    entries = read_jsonl(store.run_dir("L30") / "audit.jsonl")
    assert sum(e["type"] == "policy.denied" for e in entries) <= runs.DENIAL_LOG_CAP
    assert len(read_jsonl(store.vault_path("L30"))) <= runs.DENIAL_LOG_CAP + 10, "signed checkpoints grew with anonymous requests"
    assert elapsed < 60
    runs.release("L30")
    assert_consistent_terminal("L30", "RELEASED")
    released = [e for e in read_jsonl(store.run_dir("L30") / "audit.jsonl") if e["type"] == "run.released"][0]
    assert released["data"]["denials_suppressed"] >= 500  # the suppressed count is bound into the signed release event


def test_P2L31_denial_flood_after_release_is_bounded():
    sealed_run("L31")
    runs.release("L31")
    c = TestClient(api.app, raise_server_exceptions=False)
    for _ in range(runs.DENIAL_LOG_CAP + 300):
        c.get("/api/runs/L31/events")
        c.get("/api/runs/L31/artifacts")
    post = read_jsonl(store.run_dir("L31") / "post_terminal.jsonl")
    assert len(post) <= runs.POST_TERMINAL_CAP
    assert_consistent_terminal("L31", "RELEASED")


def test_P2L32_oversized_or_negative_policy_values_are_rejected():
    for bucket in (-1, 5001, 10 ** 9, True, "250"):
        with pytest.raises(runs.GateError):
            runs.create_run("L32", timing_bucket_ms=bucket)
    with pytest.raises(runs.GateError):
        runs.create_run("L32", tags=["x"] * 21)
    with pytest.raises(runs.GateError):
        runs.create_run("L32", tags=["x" * 65])
    c = TestClient(api.app, raise_server_exceptions=False)
    r = c.post("/api/runs", json={"run_id": "L32-API", "timing_bucket_ms": 10 ** 9}, headers={"X-Aegis-Token": store.tokens()["operator"]})
    assert r.status_code == 409


# ------------------------------------------------------------------ matrix wrapper
def test_P2L40_extended_access_matrix_has_no_unauthorized_success():
    import phase2_matrix as pm
    rep = pm.run_extended_matrix()
    t = rep["totals"]
    assert t["unexpectedly_permitted"] == 0 and t["wrongly_denied"] == 0 and t["test_errors"] == 0 and t["secret_hits"] == 0, rep["mismatches"]
    assert t["attempted"] >= 500 and rep["mismatches"] == []
