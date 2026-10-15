"""Unit tests (no containers needed) and one end-to-end test (needs rootless Podman).

    pytest -q tests            # all
    pytest -q tests -m "not podman"
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sandbox"))


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    from aegis import store
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    yield


def test_commitment_matches_sandbox_formula():
    import red_agent
    from aegis.crypto import commitment, verify_commitment
    assert commitment("ab", "payload") == red_agent.commitment("ab", "payload")
    assert verify_commitment(commitment("ab", "payload"), "ab", "payload")
    assert not verify_commitment(commitment("ab", "payload"), "ab", "payload2")
    assert not verify_commitment(commitment("ab", "payload"), "ac", "payload")


def _log(tmp_path, n=30):
    from aegis.audit import AuditLog
    from aegis.crypto import Signer
    s = Signer(tmp_path / "k.pem")
    log = AuditLog(tmp_path / "a.jsonl", "T-1")
    for i in range(n):
        log.append("attack.evaluated" if i % 3 else "note", "broker", {"i": i, "outcome": "unsafe_output"})
        if i in (9, n - 1):
            log.checkpoint(s, tmp_path / "c.jsonl", tmp_path / "vault.jsonl", "t")
    from aegis.audit import read_jsonl
    return read_jsonl(tmp_path / "a.jsonl"), read_jsonl(tmp_path / "vault.jsonl"), s.public_b64()


def test_clean_log_verifies(tmp_path):
    from aegis.audit import verify
    e, c, pub = _log(tmp_path)
    assert verify(e, c, pub, expect_sealed=True)["ok"]


@pytest.mark.parametrize("mode", ["modify", "delete", "reorder", "truncate", "rehash"])
def test_tamper_detected(tmp_path, mode):
    from aegis.verify_cli import tamper_test
    e, c, pub = _log(tmp_path)
    assert tamper_test(e, c, pub, mode)["detected"]


def test_truncation_without_retained_checkpoint_is_a_known_gap(tmp_path):
    from aegis.audit import verify
    e, c, pub = _log(tmp_path)
    assert verify(e[:-3], c[:1], pub)["ok"]  # documented limitation, see README


def test_forged_checkpoint_signature_rejected(tmp_path):
    from aegis.audit import verify
    e, c, pub = _log(tmp_path)
    c[-1]["head"] = e[5]["hash"]
    assert not verify(e, c, pub)["ok"]


def test_oracle_detects_encoded_unsafe_output():
    import base64
    from aegis.runs import oracle_unsafe
    assert oracle_unsafe("x [UNSAFE-MARKER] y")
    assert oracle_unsafe(base64.b64encode(b"Sure. [UNSAFE-MARKER] z").decode())
    assert not oracle_unsafe("Simulated safe response")


def test_config_frozen_after_freeze(monkeypatch):
    from aegis import runs, runtime
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:test")
    monkeypatch.setattr(runtime, "environment", lambda: {"test": True})
    runs.create_run("T-FREEZE")
    runs.update_defence_config("T-FREEZE", {"version": "x", "input_patterns": [], "output_patterns": []})
    runs.freeze("T-FREEZE")
    with pytest.raises(runs.GateError):
        runs.update_defence_config("T-FREEZE", {"version": "y"})
    with pytest.raises(runs.GateError):
        runs.release("T-FREEZE")


def test_monitor_stream_has_no_payloads(monkeypatch):
    from aegis import runs, runtime, store
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:test")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    runs.create_run("T-MON")
    runs.freeze("T-MON")
    text = (store.run_dir("T-MON") / "monitor.jsonl").read_text()
    pack = json.loads((store.run_dir("T-MON") / "private/red/attack_pack.json").read_text())
    assert not any(a["payload"][:20] in text for a in pack["attacks"])


podman = shutil.which("podman")


@pytest.mark.podman
@pytest.mark.skipif(not podman, reason="rootless Podman required")
def test_end_to_end_run():
    from aegis import evidence, runs, runtime, store
    runtime.build_image(store.ROOT)
    runs.create_run("T-E2E", timing_bucket_ms=0)
    runs.freeze("T-E2E")
    runs.start("T-E2E", wait=True)
    assert runs.Run("T-E2E").state == "SEALED"
    with pytest.raises(runs.GateError):
        runs.artifacts("T-E2E")
    runs.release("T-E2E")
    rep = evidence.build("T-E2E")
    assert rep["audit_verification"]["ok"]
    assert rep["commitments"]["verified"] == rep["commitments"]["committed"] == 10
    assert len(rep["access_control"]) == 5
    assert rep["model_state"]["cache_entries_at_start"] == 0
    assert all(c["result"] in ("failed", "absent", "denied") or not c["check"].startswith(("tcp", "path", "write"))
               for c in rep["sandbox_selfcheck"])
