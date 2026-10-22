"""Local control-plane API and website host.

Run:  uvicorn aegis.api:app --host 127.0.0.1 --port 8400

Identities are local demo tokens (var/keys/tokens.json). The API enforces them;
production would use SSO/OIDC with run-scoped claims. GET /api/demo/identities
exposes the tokens to the local website only when AEGIS_DEMO_MODE=1.
"""
import hmac
import os
import re

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import evidence, runtime, store
from . import runs as runs_mod
from .audit import read_jsonl
from .runs import GateError, Run, artifacts, create_run, freeze, list_runs, release, start, update_defence_config, verify_run
from .verify_cli import TAMPER_MODES, tamper_test

app = FastAPI(title="AegisLab control plane (prototype)", version="0.1")
WEB = store.ROOT / "web"


def role_of(token: str | None) -> str:
    if not token:
        return "observer"
    found = None
    for role, tok in store.tokens().items():  # constant-time compare against every token
        if hmac.compare_digest(tok.encode(), token.encode()):
            found = role
    if found is None:
        raise HTTPException(401, "unknown identity token")
    return found


def need(token, *roles):
    role = role_of(token)
    if role not in roles:
        raise HTTPException(403, "role '%s' is not permitted; requires %s" % (role, " or ".join(roles)))
    return role


def get_run(run_id) -> Run:
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]{1,31}", run_id) or not store.run_dir(run_id).exists():
        raise HTTPException(404, "run not found")
    return Run(run_id)


def gate(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except GateError as exc:
        raise HTTPException(409, str(exc))


def public_view(rec: dict) -> dict:
    keys = ("id", "state", "created_at", "frozen_at", "started_at", "sealed_at", "released_at", "policy", "tags",
            "attack_count", "evaluated", "manifest_digest", "commitments_root", "model_cache_at_start", "complete")
    out = {k: rec.get(k) for k in keys}
    out["outcomes"] = rec.get("outcomes") if rec.get("state") == "RELEASED" else None
    return out


class CreateReq(BaseModel):
    run_id: str
    timing_bucket_ms: int = 250
    tags: list[str] = []


class TamperReq(BaseModel):
    mode: str


@app.get("/api/health")
def health():
    return {"ok": True, "service": "aegislab-control-plane", "mode": "local prototype"}


@app.get("/api/meta")
def meta():
    manifest_env = None
    for rec in list_runs():
        m = store.read_json(store.run_dir(rec["id"]) / "manifest.json")
        if m:
            manifest_env = m.get("environment")
            break
    return {"environment": manifest_env, "image": runtime.IMAGE, "tamper_modes": TAMPER_MODES,
            "demo_mode": os.environ.get("AEGIS_DEMO_MODE") == "1"}


@app.get("/api/demo/identities")
def identities():
    if os.environ.get("AEGIS_DEMO_MODE") != "1":
        raise HTTPException(404, "demo identities disabled")
    return {"note": "Local demo identities issued by this control plane. Not for production use.",
            "tokens": store.tokens()}


@app.get("/api/whoami")
def whoami(x_aegis_token: str | None = Header(None)):
    return {"role": role_of(x_aegis_token)}


@app.get("/api/runs")
def runs():
    return [public_view(r) for r in list_runs()]


@app.post("/api/runs")
def create(req: CreateReq, x_aegis_token: str | None = Header(None)):
    need(x_aegis_token, "operator")
    return public_view(gate(create_run, req.run_id, timing_bucket_ms=req.timing_bucket_ms, tags=req.tags).record)


SECRET_DIGESTS = ("defence_config_digest", "attack_pack_digest")


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str, x_aegis_token: str | None = Header(None)):
    """Digests of the blue config and red attack pack are a guess-confirmation oracle (a team that can guess
    the file, e.g. the sample config, could confirm it by hashing), so only the operator and reviewer see them
    before release."""
    run = get_run(run_id)
    role = role_of(x_aegis_token)
    manifest = store.read_json(run.dir / "manifest.json") or {}
    show_secret = role in ("operator", "reviewer") or run.state == "RELEASED"
    keys = ("sandbox_image_id", "base_image_digest", "signing_key_id", "hardening_flags", "environment",
            "frozen_at") + (SECRET_DIGESTS if show_secret else ())
    return {**public_view(run.record), "manifest": {k: manifest.get(k) for k in keys} if manifest else None}


@app.get("/api/runs/{run_id}/events")
def events(run_id: str):
    """Redacted monitoring stream: no payloads, outputs or defence rules."""
    return read_jsonl(get_run(run_id).dir / "monitor.jsonl")


@app.post("/api/runs/{run_id}/freeze")
def do_freeze(run_id: str, x_aegis_token: str | None = Header(None)):
    need(x_aegis_token, "operator")
    get_run(run_id)
    gate(freeze, run_id)
    return run_detail(run_id, x_aegis_token)


@app.post("/api/runs/{run_id}/defence-config")
def change_config(run_id: str, body: dict, x_aegis_token: str | None = Header(None)):
    role = need(x_aegis_token, "blue_participant", "operator")
    get_run(run_id)
    gate(update_defence_config, run_id, body, actor=role)
    return {"ok": True}


@app.post("/api/runs/{run_id}/start")
def do_start(run_id: str, x_aegis_token: str | None = Header(None)):
    need(x_aegis_token, "operator")
    get_run(run_id)
    gate(start, run_id)
    return {"ok": True, "state": "RUNNING"}


@app.post("/api/runs/{run_id}/release")
def do_release(run_id: str, x_aegis_token: str | None = Header(None)):
    role = role_of(x_aegis_token)
    run = get_run(run_id)
    if role != "reviewer":
        run.log("policy.denied", role, {"op": "release", "reason": "not an authorised reviewer"},
                monitor={"summary": "Release attempt by %s rejected" % role, "decision": "denied"})
        raise HTTPException(403, "only an authorised reviewer can release results")
    return gate(release, run_id)


@app.get("/api/runs/{run_id}/artifacts")
def get_artifacts(run_id: str, x_aegis_token: str | None = Header(None)):
    role = role_of(x_aegis_token)
    run = get_run(run_id)
    if role not in ("reviewer", "blue_participant", "red_participant") or run.state != "RELEASED":
        run.log("policy.denied", role, {"op": "read_artifacts", "reason": "sealed until release" if role != "observer"
                                        else "no identity"},
                monitor={"summary": "Artifact access by %s rejected (%s)" % (role, run.state), "decision": "denied"})
        raise HTTPException(403, "attack artifacts are sealed until an authorised reviewer releases them")
    return gate(artifacts, run_id)


@app.get("/api/runs/{run_id}/verify")
def do_verify(run_id: str):
    get_run(run_id)
    return verify_run(run_id)


@app.post("/api/runs/{run_id}/tamper-test")
def do_tamper(run_id: str, req: TamperReq, x_aegis_token: str | None = Header(None)):
    need(x_aegis_token, "reviewer", "operator")
    run = get_run(run_id)
    if req.mode not in TAMPER_MODES:
        raise HTTPException(400, "unknown mode")
    anchor_file = store.anchor_path(run_id)
    res = tamper_test(read_jsonl(run.dir / "audit.jsonl"), read_jsonl(store.vault_path(run_id)),
                      runs_mod.signer().public_b64(), req.mode, run_id=run_id,
                      anchor=store.read_json(anchor_file) if anchor_file.exists() else None,
                      expected_state=run.state if run.state in ("RELEASED", "FAILED") else None)
    res["note"] = "Tampering applied to an in-memory copy; the stored audit log is unchanged."
    return res


@app.get("/api/runs/{run_id}/evidence")
def get_evidence(run_id: str, x_aegis_token: str | None = Header(None)):
    run = get_run(run_id)
    role = role_of(x_aegis_token)
    if run.state != "RELEASED" and role != "reviewer":
        raise HTTPException(403, "evidence report is available after release")
    return evidence.build(run_id)


@app.get("/api/runs/{run_id}/evidence.md", response_class=PlainTextResponse)
def get_evidence_md(run_id: str, x_aegis_token: str | None = Header(None)):
    rep = get_evidence(run_id, x_aegis_token)
    return PlainTextResponse(evidence.markdown(rep), headers={
        "Content-Disposition": 'attachment; filename="%s_evidence.md"' % run_id})


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


app.mount("/", StaticFiles(directory=WEB), name="web")
