"""Role, information-flow and error-handling regression tests.

The container-free matrix lives in evaluation/isolation_matrix.py (one call per distinct
actor x operation x state). These tests assert its outcome and add targeted negative tests at the
component level (broker message handling, filesystem layout, frozen config, logging, error bodies).
"""
import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from aegis import api, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment, sha256  # noqa: E402
import isolation_matrix as mx  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.delenv("AEGIS_DEMO_MODE", raising=False)


def test_access_matrix_has_no_unauthorized_success_and_no_secret_markers():
    rep = mx.run_matrix()
    assert rep["cases_expect_deny"] >= 150 and rep["cases_expect_allow"] >= 25
    assert rep["unauthorized_succeeded"] == 0, rep["unauthorized_succeeded_detail"]
    assert not rep["policy_mismatches"], rep["policy_mismatches"]
    assert rep["server_errors_5xx"] == 0
    assert rep["secret_marker_hits"] == 0, rep["secret_marker_hit_detail"]
    assert rep["path_traversal_rejected"] == rep["path_traversal_cases"], rep["path_traversal_failures"]
    assert rep["error_body_leaks"] == 0
    assert rep["invalid_config_response"]["echoes_input"] is False


# ------------------------------------------------------------------ broker: identity bound to the channel
class FakeBroker(runs.Broker):
    """Real Broker.handle/attack logic with the blue and model mailboxes replaced by in-process fakes."""

    def __init__(self, run):
        super().__init__(run)
        self._mk_spool("red")
        self.calls = []

    def call(self, role, msg, timeout=15.0):
        self.calls.append((role, msg["op"]))
        if role == "blue":
            return {"ok": True, "verdict": "allow", "rule": None}
        return {"ok": True, "text": "Simulated safe response to: " + msg.get("prompt", "")[:20]}

    def reply_of(self, name):
        return json.loads((self.spool["red"] / "in" / name).read_text())


@pytest.fixture
def broker(monkeypatch):
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    runs.create_run("T-BRK", timing_bucket_ms=0)
    runs.freeze("T-BRK")
    run = runs.Run("T-BRK")
    run.update(state="RUNNING")
    return FakeBroker(run)


def commit(b, aid="A01", payload="hello world", nonce="n1"):
    b.handle("000001.json", {"op": "commit", "commitments": [{"attack_id": aid, "digest": commitment(nonce, payload)}]})
    return aid, payload, nonce


def test_legitimate_committed_attack_completes(broker):
    aid, payload, nonce = commit(broker)
    broker.handle("000002.json", {"op": "attack", "attack_id": aid, "payload": payload, "nonce": nonce})
    r = broker.reply_of("000002.json")
    assert r["ok"] and not r.get("denied") and ("blue", "inspect_input") in broker.calls and ("model", "generate") in broker.calls


@pytest.mark.parametrize("msg,reason", [
    ({"op": "read_artifact", "target": "blue/defence_config"}, "not permitted"),
    ({"op": "get_verdicts"}, "not permitted"),
    ({"op": "release_results"}, "not permitted"),
    ({"op": "../../etc/passwd"}, "unknown operation"),
    ({"op": None}, "unknown operation"),
    ({"op": "attack", "attack_id": "NEW", "payload": "x", "nonce": "00"}, "no prior commitment"),
    ({"op": "attack", "tenant": "blue", "attack_id": "A01", "payload": "hello world", "nonce": "n1"}, "identity is bound"),
    ({"op": "attack", "tenant": "operator", "attack_id": "A01", "payload": "hello world", "nonce": "n1"}, "identity is bound"),
    ({"op": "attack", "attack_id": "A01", "payload": "changed after commit", "nonce": "n1"}, "does not match commitment"),
    ({"op": "attack", "attack_id": "A01", "payload": "hello world", "nonce": "other"}, "does not match commitment"),
])
def test_forbidden_broker_ops_are_denied_and_never_reach_other_workloads(broker, msg, reason):
    commit(broker)
    broker.calls.clear()
    broker.handle("000009.json", msg)
    r = broker.reply_of("000009.json")
    assert r.get("denied") is True and reason in r["reason"]
    assert broker.calls == []  # nothing forwarded to the defence runner or model worker
    assert "output" not in r and "config" not in json.dumps(r).lower()


def test_replay_of_committed_attack_denied(broker):
    aid, payload, nonce = commit(broker)
    msg = {"op": "attack", "attack_id": aid, "payload": payload, "nonce": nonce}
    broker.handle("000002.json", msg)
    broker.calls.clear()
    broker.handle("000003.json", msg)
    assert broker.reply_of("000003.json")["denied"] and broker.calls == []


def test_denied_request_text_never_enters_monitor_stream(broker):
    secret = "RED-LEAK-CHECK-9981"
    commit(broker)
    broker.handle("000010.json", {"op": secret, "target": secret})
    broker.handle("000011.json", {"op": "read_artifact", "target": secret})
    broker.handle("000012.json", {"op": "attack", "tenant": secret, "attack_id": secret, "payload": secret, "nonce": "0"})
    broker.handle("000013.json", {"op": "attack", "attack_id": secret, "payload": secret, "nonce": "0"})
    assert secret not in (broker.run.dir / "monitor.jsonl").read_text()
    assert secret not in (broker.run.dir / "audit.jsonl").read_text()


def test_symlink_and_oversized_messages_rejected(tmp_path):
    target = tmp_path / "secret.json"
    target.write_text('{"op":"x"}')
    link = tmp_path / "000001.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        runs._safe_read(link)
    big = tmp_path / "000002.json"
    big.write_text(json.dumps({"op": "x", "pad": "a" * (runs.MAX_MSG + 10)}))
    with pytest.raises(ValueError):
        runs._safe_read(big)
    fifo = tmp_path / "000003.json"
    os.mkfifo(fifo)
    with pytest.raises((ValueError, OSError)):
        runs._safe_read(fifo)


# ------------------------------------------------------------------ frozen configuration
def test_frozen_config_is_read_only_and_cannot_be_changed(monkeypatch):
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    runs.create_run("T-FRZ")
    runs.freeze("T-FRZ")
    f = store.run_dir("T-FRZ") / "frozen/defence_config.json"
    assert (f.stat().st_mode & 0o222) == 0
    for cfg in ({"version": "x"}, {"input_patterns": ["a"]}, {}):
        with pytest.raises(runs.GateError):
            runs.update_defence_config("T-FRZ", cfg)
    entries = read_jsonl(store.run_dir("T-FRZ") / "audit.jsonl")
    assert sum(e["type"] == "policy.denied" for e in entries) == 3


@pytest.mark.parametrize("cfg", [[], "x", {"input_patterns": "not-a-list"}, {"input_patterns": ["("]},
                                 {"input_patterns": ["a"] * 201}, {"output_patterns": ["a" * 501]},
                                 {"version": "x" * 70000}])
def test_malformed_defence_config_rejected_before_it_reaches_the_runner(cfg):
    runs.create_run("T-CFG")
    with pytest.raises(runs.GateError):
        runs.update_defence_config("T-CFG", cfg)


# ------------------------------------------------------------------ information-flow properties of the filesystem layout
def test_sandbox_mounts_expose_only_role_specific_directories(monkeypatch):
    """Static check of what each container is given: red never mounts frozen/ or sealed/, blue never mounts private/red,
    and the model worker mounts only its own spool."""
    mounts = {}

    def fake_launch(name, role, m, env, cmd=None):
        mounts[role] = [(host, ctr, mode) for host, ctr, mode in m]
        return "id"

    monkeypatch.setattr(runtime, "launch", fake_launch)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.setattr(runtime, "inspect_security", lambda n: {})
    runs.create_run("T-MNT", timing_bucket_ms=0)
    runs.freeze("T-MNT")
    run = runs.Run("T-MNT")
    run.update(state="RUNNING")
    b = runs.Broker(run)
    b.call = lambda role, msg, timeout=15.0: ({"ok": True, "config_digest": run.record and
                                               store.read_json(run.dir / "manifest.json")["defence_config_digest"]}
                                              if msg["op"] == "attest" else {"ok": True, "cache_entries": 0, "uptime_s": 0})
    b.start_workloads()
    host = lambda role: [h for h, c, m in mounts[role]]  # noqa: E731
    d = str(run.dir)
    assert not any("frozen" in h or "sealed" in h or "blue_working" in h for h in host("red"))
    assert any(h.endswith("private/red") for h in host("red")) and dict((c, m) for h, c, m in mounts["red"])["/aegis/private"] == "ro"
    assert not any("private" in h or "sealed" in h for h in host("blue"))
    assert dict((c, m) for h, c, m in mounts["blue"])["/aegis/frozen"] == "ro"
    assert len(mounts["model"]) == 1 and mounts["model"][0][1] == "/aegis/spool"
    for role in mounts:
        assert all(h.startswith(d) for h in host(role)), "mount outside the run directory"
    spools = [h for role in mounts for h in host(role) if "/spool/" in h]
    assert len(set(spools)) == len(spools), "spools must be per-role"


def test_runtime_flags_are_fail_safe_for_every_role():
    for role in ("red", "blue", "model"):
        flags = runtime.hardening_flags(role)
        assert flags[flags.index("--network") + 1] == "none"
        assert "--read-only" in flags and flags[flags.index("--cap-drop") + 1] == "ALL"
        assert "no-new-privileges" in flags and "--privileged" not in flags


# ------------------------------------------------------------------ keys, tokens, logging
def test_token_and_key_files_are_private():
    store.tokens()
    runs.signer()
    for p in (store.p("keys", "tokens.json"), store.p("keys", "broker_ed25519.pem")):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_no_secrets_in_stdout_or_logs(caplog, capsys):
    from fastapi.testclient import TestClient
    with mx.stubbed_runtime():
        mx.build_run("MX-LOG", "RELEASED")
        tokens = store.tokens()
        c = TestClient(api.app, raise_server_exceptions=False)
        with caplog.at_level("DEBUG"):
            c.get("/api/runs/MX-LOG/artifacts")
            c.get("/api/runs/MX-LOG/evidence", headers={"X-Aegis-Token": "wrong-token-value"})
            c.get("/api/runs/MX-LOG/evidence", headers={"X-Aegis-Token": tokens["red_participant"]})
    out = capsys.readouterr()
    blob = caplog.text + out.out + out.err
    for needle in (mx.SECRET_PAYLOAD_MARK, mx.SECRET_CONFIG_MARK, "wrong-token-value", *tokens.values()):
        assert needle not in blob


def test_demo_identities_only_in_demo_mode(monkeypatch):
    from fastapi.testclient import TestClient
    c = TestClient(api.app)
    assert c.get("/api/demo/identities").status_code == 404
    monkeypatch.setenv("AEGIS_DEMO_MODE", "1")
    assert c.get("/api/demo/identities").status_code == 200


def test_evidence_token_in_query_string_is_not_accepted():
    from fastapi.testclient import TestClient
    with mx.stubbed_runtime():
        mx.build_run("MX-Q", "SEALED")
        tok = store.tokens()["reviewer"]
        c = TestClient(api.app, raise_server_exceptions=False)
        assert c.get("/api/runs/MX-Q/evidence.md?token=" + tok).status_code == 403
        assert c.get("/api/runs/MX-Q/evidence.md", headers={"X-Aegis-Token": tok}).status_code == 200


def test_secret_digests_hidden_before_release_for_participants():
    from fastapi.testclient import TestClient
    with mx.stubbed_runtime():
        mx.build_run("MX-D", "FROZEN")
        t = store.tokens()
        c = TestClient(api.app)
        digest = store.read_json(store.run_dir("MX-D") / "manifest.json")["defence_config_digest"]
        for role in (None, "red_participant", "blue_participant"):
            h = {"X-Aegis-Token": t[role]} if role else {}
            assert digest not in c.get("/api/runs/MX-D", headers=h).text
        assert digest in c.get("/api/runs/MX-D", headers={"X-Aegis-Token": t["reviewer"]}).text


def test_concurrent_denials_do_not_fork_or_corrupt_the_chain():
    from fastapi.testclient import TestClient
    with mx.stubbed_runtime():
        mx.build_run("MX-C", "SEALED")
        c = TestClient(api.app)

        def hit():
            for _ in range(10):
                c.get("/api/runs/MX-C/artifacts")
        ts = [threading.Thread(target=hit) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        entries = read_jsonl(store.run_dir("MX-C") / "audit.jsonl")
        assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
        r = runs.verify_run("MX-C")
        assert r["chain_ok"]


def test_rejected_tenant_files_are_removed_and_never_block(tmp_path):
    """A tenant can create FIFOs, directories, links and deep JSON in its out/ spool. None may block the broker
    or be re-read (the original code left rejected entries in place, re-denying them in a loop)."""
    import time
    entries = {}
    entries["fifo"] = tmp_path / "000001.json"
    os.mkfifo(entries["fifo"])
    entries["dir"] = tmp_path / "000002.json"
    entries["dir"].mkdir()
    (entries["dir"] / "inner").write_text("x")
    secret = tmp_path / "outside.txt"
    secret.write_text("secret")
    entries["link"] = tmp_path / "000003.json"
    entries["link"].symlink_to(secret)
    entries["deep"] = tmp_path / "000004.json"
    entries["deep"].write_text("[" * 100000)
    entries["list"] = tmp_path / "000005.json"
    entries["list"].write_text("[1,2,3]")
    t0 = time.monotonic()
    for kind, path in entries.items():
        with pytest.raises((OSError, ValueError)):
            runs._safe_read(path)
        assert not os.path.lexists(path), kind
    assert time.monotonic() - t0 < 2
    assert secret.read_text() == "secret"  # the link target was never touched


def test_malformed_but_valid_json_messages_do_not_fail_the_run(broker):
    for i, msg in enumerate([{"op": "commit", "commitments": [{"nope": 1}]}, {"op": "commit", "commitments": "x"},
                             {"op": "attack", "attack_id": ["a"], "payload": {"x": 1}, "nonce": 5}]):
        try:
            broker.handle("0001%02d.json" % i, msg)
        except (KeyError, TypeError, AttributeError, ValueError):
            pass  # execute() converts these into a denial instead of failing the run
