"""Finale P4, SHOULD 6: signed, expiring capability tokens scoped to (run, role, operations), signed with a key separate from
the evidence key. Real API (aegis.api) through FastAPI's TestClient; runs are driven to SEALED in-process.
"""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, captoken, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(captoken, "_signers", {})
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


@pytest.fixture
def c():
    return TestClient(api.app)


def tok(role):
    return {"X-Aegis-Token": store.tokens()[role]}


def sealed(rid):
    runs.create_run(rid, timing_bucket_ms=0)
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    run.log("attack.evaluated", "broker", {"attack_id": "A00"})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED", outcomes={"safe_output": 1})
    run.checkpoint("seal")
    store.append_jsonl(run.dir / "sealed/artifacts.jsonl", {"attack_id": "A00", "payload": "P", "nonce": "n"})
    store.write_json(run.dir / "sealed/commitments.json", {"A00": commitment("n", "P")})
    return run


def mint(c, issuer, rid, role, ops, ttl=600):
    r = c.post("/api/runs/%s/capabilities" % rid, json={"role": role, "ops": ops, "ttl_s": ttl}, headers=tok(issuer))
    return r


def cap(t):
    return {"X-Aegis-Token": t}


def test_P4K01_a_capability_works_on_its_run_for_its_operations_only(c):
    sealed("T-K01")
    sealed("T-K01B")
    r = mint(c, "operator", "T-K01", "red_participant", ["detail", "events"])
    assert r.status_code == 200, r.text
    t = r.json()["token"]
    assert c.get("/api/runs/T-K01", headers=cap(t)).status_code == 200
    assert c.get("/api/runs/T-K01/events", headers=cap(t)).status_code == 200
    assert c.get("/api/runs/T-K01B", headers=cap(t)).status_code == 403  # another run
    assert c.get("/api/runs/T-K01/artifacts", headers=cap(t)).status_code == 403  # an operation it does not list
    assert c.get("/api/whoami", headers=cap(t)).status_code == 401  # not a global token
    assert c.post("/api/runs", json={"run_id": "T-K01C"}, headers=cap(t)).status_code == 401


def test_P4K02_a_capability_never_widens_its_role(c):
    sealed("T-K02")
    assert mint(c, "operator", "T-K02", "red_participant", ["release"]).status_code == 400
    assert mint(c, "operator", "T-K02", "blue_participant", ["start"]).status_code == 400
    assert mint(c, "operator", "T-K02", "red_participant", []).status_code == 400


def test_P4K03_only_the_reviewer_can_mint_the_right_to_release(c):
    sealed("T-K03")
    assert mint(c, "operator", "T-K03", "reviewer", ["release"]).status_code == 403
    assert mint(c, "red_participant", "T-K03", "red_participant", ["detail"]).status_code == 403
    assert c.post("/api/runs/T-K03/capabilities", json={"role": "red_participant", "ops": ["detail"]}).status_code == 403  # observer
    r = mint(c, "reviewer", "T-K03", "reviewer", ["release"])
    assert r.status_code == 200
    rel = c.post("/api/runs/T-K03/release", headers=cap(r.json()["token"]))
    assert rel.status_code == 200 and runs.Run("T-K03").state == "RELEASED", rel.text


def test_P4K04_expired_tampered_and_foreign_key_tokens_are_refused(c, monkeypatch):
    sealed("T-K04")
    t = mint(c, "operator", "T-K04", "red_participant", ["detail"], ttl=1).json()["token"]
    import time as _t
    real = _t.time
    monkeypatch.setattr(captoken.time, "time", lambda: real() + 2)
    assert c.get("/api/runs/T-K04", headers=cap(t)).status_code == 401
    monkeypatch.setattr(captoken.time, "time", real)
    t = mint(c, "operator", "T-K04", "red_participant", ["detail"]).json()["token"]
    body, sig = t[len(captoken.PREFIX):].split(".")
    claims = json.loads(captoken._unb64(body))
    claims["ops"] = ["artifacts", "detail"]
    forged = captoken.PREFIX + captoken._b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()) + "." + sig
    assert c.get("/api/runs/T-K04", headers=cap(forged)).status_code == 401
    assert c.get("/api/runs/T-K04", headers=cap(t[:-4] + "AAAA")).status_code == 401
    # a token signed with the EVIDENCE key is not a capability
    ev = runs.signer()
    claims = json.loads(captoken._unb64(body))
    esig = captoken._b64(base64.b64decode(ev.sign(claims)))
    assert c.get("/api/runs/T-K04", headers=cap(captoken.PREFIX + body + "." + esig)).status_code == 401
    assert c.get("/api/runs/T-K04", headers=cap(t)).status_code == 200


def test_P4K05_the_capability_key_is_separate_and_private(c):
    sealed("T-K05")
    mint(c, "operator", "T-K05", "red_participant", ["detail"])
    k = store.p("keys", "capability_ed25519.pem")
    assert k.is_file() and (k.stat().st_mode & 0o077) == 0
    assert captoken.signer().public_b64() != runs.signer().public_b64()
    assert k.parent == store.p("keys", "broker_ed25519.pem").parent  # refused as a mount source (runtime._check_mounts)
    assert any(str(k).startswith(str(s)) for s in runtime._secret_paths())


def test_P4K06_issuance_is_audited_without_the_token_and_refusals_on_the_result_gate_are_denials(c):
    sealed("T-K06")
    r = mint(c, "operator", "T-K06", "red_participant", ["detail"])
    t = r.json()["token"]
    audit = read_jsonl(runs.Run("T-K06").dir / "audit.jsonl")
    iss = [e for e in audit if e["type"] == "capability.issued"]
    assert len(iss) == 1 and iss[0]["data"]["jti"] == r.json()["claims"]["jti"] and t not in json.dumps(audit)
    assert c.get("/api/runs/T-K06/artifacts", headers=cap(t)).status_code == 403
    assert c.post("/api/runs/T-K06/release", headers=cap(t)).status_code == 403
    den = [e["data"] for e in read_jsonl(runs.Run("T-K06").dir / "audit.jsonl") if e["type"] == "policy.denied"]
    assert {d["op"] for d in den} >= {"read_artifacts", "release"}
    assert runs.Run("T-K06").state == "SEALED"


def test_P4K07_lifetime_is_bounded(c):
    sealed("T-K07")
    assert mint(c, "operator", "T-K07", "red_participant", ["detail"], ttl=captoken.MAX_TTL_S + 1).status_code == 400
    assert mint(c, "operator", "T-K07", "red_participant", ["detail"], ttl=0).status_code == 400
    claims = mint(c, "operator", "T-K07", "red_participant", ["detail"], ttl=captoken.MAX_TTL_S).json()["claims"]
    assert claims["exp"] - claims["iat"] == captoken.MAX_TTL_S


def test_P4K08_global_role_tokens_are_unchanged(c):
    sealed("T-K08")
    assert c.get("/api/whoami", headers=tok("red_participant")).json() == {"role": "red_participant"}
    assert c.get("/api/runs/T-K08/artifacts", headers=tok("red_participant")).status_code == 403
    assert c.post("/api/runs/T-K08/release", headers=tok("reviewer")).status_code == 200
