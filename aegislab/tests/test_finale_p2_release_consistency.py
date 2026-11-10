"""Finale P2, item 5: a release whose strict verification fails AFTER the RELEASED terminal checkpoint was signed.

Confirmed on the pre-P2 code: runs._release_locked signed the terminal checkpoint with state RELEASED, then set the record to
FAILED when the final verification failed. The signed evidence then said RELEASED while the record said FAILED, and every later
verification failed on that mismatch (made by the control plane itself) instead of reporting the genuine finding.

Now the record stays consistent with its signature (RELEASED), the release is marked unverified, nothing behind the result gate
is handed out, and an unsigned post-terminal entry records why. The genuine finding is what verification reports.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


def sealed_run(rid):
    runs.create_run(rid, timing_bucket_ms=0)
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    run.log("attack.evaluated", "broker", {"attack_id": "A00"})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED", outcomes={"safe_output": 1})
    run.checkpoint("seal")
    store.append_jsonl(run.dir / "sealed/artifacts.jsonl", {"attack_id": "A00", "payload": "SEALED-PAYLOAD-MARKER", "nonce": "n"})
    store.write_json(run.dir / "sealed/commitments.json", {"A00": commitment("n", "SEALED-PAYLOAD-MARKER")})
    return run


def fail_after_signing(monkeypatch, how):
    """Make the strict verification after the terminal checkpoint fail, the way storage damage after signing would."""
    real = runs.verify_run

    def verify_run(run_id, tail_ok=False):
        if not tail_ok and store.anchor_path(run_id).exists():
            how(run_id)
        return real(run_id, tail_ok=tail_ok)
    monkeypatch.setattr(runs, "verify_run", verify_run)
    return real


def drop_anchor(run_id):
    store.anchor_path(run_id).chmod(0o644)
    store.anchor_path(run_id).unlink()


def test_item5_record_stays_consistent_with_the_signed_terminal_state(monkeypatch):
    run = sealed_run("R5-A")
    real = fail_after_signing(monkeypatch, drop_anchor)
    with pytest.raises(runs.GateError, match="results withheld"):
        runs.release("R5-A")
    monkeypatch.setattr(runs, "verify_run", real)
    vault_terminal = [c for c in read_jsonl(store.vault_path("R5-A")) if c.get("reason") == "terminal"]
    assert len(vault_terminal) == 1 and vault_terminal[0]["state"] == "RELEASED"
    assert run.state == "RELEASED", "the record must agree with the state its terminal checkpoint signed"
    assert run.record["release_verified"] is False and not runs.released(run.record)
    v = runs.verify_run("R5-A")
    assert not v["ok"]
    issues = " ".join(str(f) for f in v["findings"])
    assert "anchor" in issues, "verification reports the genuine finding"
    assert "differs from the run's recorded state" not in issues, "no self-made state mismatch"
    post = read_jsonl(run.dir / "post_terminal.jsonl")
    assert [p["type"] for p in post] == ["run.release_unverified"]


def test_item5_nothing_behind_the_result_gate_is_handed_out(monkeypatch):
    run = sealed_run("R5-B")
    fail_after_signing(monkeypatch, drop_anchor)
    with pytest.raises(runs.GateError):
        runs.release("R5-B")
    with pytest.raises(runs.GateError, match="did not verify"):
        runs.artifacts("R5-B")
    c = TestClient(api.app, raise_server_exceptions=False)
    tok = store.tokens()
    for role in ("blue_participant", "red_participant", "reviewer"):
        r = c.get("/api/runs/R5-B/artifacts", headers={"X-Aegis-Token": tok[role]})
        assert r.status_code in (403, 409) and "SEALED-PAYLOAD-MARKER" not in r.text, role
    for h in ({}, {"X-Aegis-Token": tok["blue_participant"]}):
        assert c.get("/api/runs/R5-B/evidence", headers=h).status_code == 403
        detail = c.get("/api/runs/R5-B", headers=h).json()
        assert detail["outcomes"] is None
        assert "defence_config_digest" not in json.dumps(detail["manifest"])
    assert run.record["state"] == "RELEASED"


def test_item5_a_normal_release_is_unchanged():
    sealed_run("R5-C")
    res = runs.release("R5-C")
    run = runs.Run("R5-C")
    assert res["state"] == "RELEASED" and res["verification"]["ok"]
    assert "release_verified" not in run.record and runs.released(run.record)
    assert runs.artifacts("R5-C")[0]["payload"] == "SEALED-PAYLOAD-MARKER"
    assert not (run.dir / "post_terminal.jsonl").exists()
