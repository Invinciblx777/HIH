"""Interactive prototype console (Phase R1, made end-to-end in Phase R2): the web UI and a small, bounded lab API around the
unchanged control plane.

Run:  scripts/start_prototype.sh
      (equivalent: AEGIS_VAR=var/console uvicorn aegis.console:app --host 127.0.0.1 --port 8400, then open the launch link
       http://127.0.0.1:8400/session/start?code=<$AEGIS_VAR/console/launch_code>)

Phase R2: the browser never holds a role token. The launch link starts an operator session (aegis/lab_session.py:
HttpOnly SameSite=Strict cookie plus a per-session CSRF token); the console performs each role's requests server-side with
the control plane's own tokens. State-changing requests from another origin are refused. AEGIS_DEMO_MODE=1 is refused at
startup because it would hand every role token to any page that can reach the port.

The control plane (aegis.api.app) is mounted unchanged: every /api/... route, role check and gate is the existing code.
This module adds /api/lab/... for things a browser cannot do safely by itself:

  * status of the host (Podman, sandbox image, model backend) so the UI can show live, degraded or replay mode;
  * a live evaluation run (operator identity: create, freeze, start through the real API handlers);
  * four allowlisted scenarios. Each one calls the real API handlers in-process with the real role tokens, then checks
    the security outcome (status code, run state, audit entry, absence of protected values), not just the HTTP result;
  * the evidence centre: a fixed registry of bundles, verified by the independent verifier program (a subprocess,
    python -m aegis.verify_cli), and tamper demonstrations on disposable copies.

Nothing here accepts a command, path, container option, network target or expression from the browser. Scenario ids,
bundle ids and tamper modes are dictionary keys; run ids must match an existing LAB-nnn run. aegis/api.py, runs.py,
evidence.py and model_client.py are deliberately not modified (their hashes are pinned by the Phase 3 evidence).
"""
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
import warnings
with warnings.catch_warnings():  # starlette's notice about httpx; the in-process client is only used for loopback calls
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from . import api, evidence, lab_session, model_client, runs, runtime, store
from .audit import entry_hash, read_jsonl
from .verify_cli import TAMPER_MODES

ROOT = store.ROOT
WEB = ROOT / "web"
CONSOLE = WEB / "console"
LAB_RUN_RE = re.compile(r"LAB-\d{3}")
MAX_LAB_RUNS = 40
MAX_BODY = 256 * 1024
VERIFY_TIMEOUT_S = 30
PROBE_TIMEOUT_S = 90
ROLES = ("operator", "reviewer", "blue_participant", "red_participant")

UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


@asynccontextmanager
async def lifespan(_app):
    if os.environ.get("AEGIS_DEMO_MODE") == "1":
        raise RuntimeError("refusing to start: AEGIS_DEMO_MODE=1 would hand every role token to any page that reaches this port. "
                           "The console uses an operator session instead (scripts/start_prototype.sh).")
    _recover_interrupted()
    lab_session.launch_code()
    yield


app = FastAPI(title="AegisLab prototype console", version="r2", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

_lab_lock = threading.Lock()                 # one state-changing lab action at a time
_verify_slots = threading.BoundedSemaphore(2)  # verifier subprocesses running at once
_cache, _cache_lock = {}, threading.Lock()


# ------------------------------------------------------------------------------------------------ request guard
def _allowed_hosts():
    return {h.strip().lower() for h in os.environ.get("AEGIS_CONSOLE_HOSTS", "127.0.0.1,localhost,[::1]").split(",") if h.strip()}


def _host_only(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):
        return host[:host.find("]") + 1] if "]" in host else host
    return host.split(":", 1)[0]


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                               "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def guard(request: Request, call_next):
    """Loopback console only: a Host header other than a loopback name is refused (stops DNS rebinding from turning a web page
    into a same-origin caller of /api/demo/identities). Body size is enforced before this, by BodyLimit."""
    if os.environ.get("AEGIS_PUBLIC_DEMO") != "1" and not os.environ.get("VERCEL") and _host_only(request.headers.get("host", "")) not in _allowed_hosts():  # public demo: read-only, no operator session can be started
        return JSONResponse({"detail": "host not allowed: the console answers on loopback names only"}, status_code=421,
                            headers=SECURITY_HEADERS)
    why = _cross_origin(request)
    if why:
        return JSONResponse({"detail": why}, status_code=403, headers=SECURITY_HEADERS)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


class BodyLimit:
    """Request-body limit on the bytes actually received (Phase R3), as plain ASGI middleware around everything, including the
    mounted control plane. A declared Content-Length above the limit, a malformed or conflicting one, and a body that grows past
    the limit while it streams in (chunked transfer, or no length at all) are refused before any handler runs: the body is read
    into a buffer of at most MAX_BODY bytes first and only then handed to the application. So an oversized request never
    reaches a handler, whether or not that handler reads its body, and cannot change session or run state. Refusals close the
    connection, because the rest of an unread body would otherwise be parsed as the next request."""

    def __init__(self, app, limit=MAX_BODY):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        lengths = [v for k, v in scope.get("headers", []) if k == b"content-length"]
        if lengths:
            if len(set(lengths)) != 1 or not lengths[0].strip().isdigit():
                return await self._refuse(send, 400, "invalid content-length")
            if int(lengths[0]) > self.limit:
                return await self._refuse(send, 413, "request body too large (limit %d bytes)" % self.limit)
        body, more = bytearray(), True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return  # the client went away before sending its body: nobody to answer
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
            if len(body) > self.limit:
                return await self._refuse(send, 413, "request body too large (limit %d bytes)" % self.limit)
        pending = [{"type": "http.request", "body": bytes(body), "more_body": False}]

        async def replay():
            return pending.pop() if pending else await receive()
        await self.app(scope, replay, send)

    @staticmethod
    async def _refuse(send, status, detail):
        payload = json.dumps({"detail": detail}).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()), (b"connection", b"close")]
        headers += [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})


app.add_middleware(BodyLimit)  # added last, so it is the outermost user middleware: it runs before guard


def _cross_origin(request: Request):
    """State-changing requests must come from this origin. Browsers send Sec-Fetch-Site and Origin on every cross-origin
    POST; a page on another port of 127.0.0.1 is 'same-site', not 'same-origin', and is refused too. Clients that send
    neither header (curl, scripts with a token) are not browsers acting for someone else."""
    if request.method not in UNSAFE_METHODS:
        return None
    site = request.headers.get("sec-fetch-site")
    if site and site not in ("same-origin", "none"):
        return "cross-origin request refused (Sec-Fetch-Site: %s)" % site[:20]
    origin = request.headers.get("origin")
    host = request.headers.get("host", "").lower()
    if origin is not None and origin.lower() not in ("http://" + host, "https://" + host):  # https when served behind a TLS proxy
        return "cross-origin request refused (Origin does not match this console)"
    return None


def _role(token):
    return api.role_of(token)  # the control plane's own constant-time token check


def _need(token, *roles):
    return api.need(token, *roles)


def _authorize(request: Request, token, *roles) -> dict:
    """Who may perform a lab action: a holder of a control-plane token with one of `roles` (scripts, tests), or the
    operator session started from the launch link (the browser), which must also present its CSRF token on writes.
    Without either the caller is an observer and is refused, as the control plane refuses observers."""
    if token is not None:
        return {"via": "token", "role": api.need(token, *roles)}
    sess = lab_session.get(request.cookies.get(lab_session.COOKIE))
    if not sess:
        raise HTTPException(403, "operator session required: open the launch link printed by scripts/start_prototype.sh")
    if request.method in UNSAFE_METHODS and not lab_session.csrf_ok(sess, request.headers.get(lab_session.CSRF_HEADER)):
        raise HTTPException(403, "missing or invalid CSRF token for this operator session")
    return {"via": "session", "role": "operator-session"}


def _cached(key, ttl, fn):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _cache_lock:
        _cache[key] = (now, val)
    return val


def _rel(path) -> str:
    """Display form of a path: relative to the project or to the state directory, never an absolute home path."""
    path = Path(path)
    for base, label in ((ROOT, ""), (store.VAR, "$AEGIS_VAR")):
        try:
            r = path.resolve().relative_to(Path(base).resolve())
            return (label + "/" + str(r)).rstrip("/.") if label else str(r)
        except ValueError:
            continue
    return path.name


# ------------------------------------------------------------------------------------------------ host status
def _podman_status() -> dict:
    if not shutil.which("podman"):
        return {"available": False, "reason": "podman is not installed or not on PATH"}
    try:
        q = subprocess.run(["podman", "info", "--format", "{{.Host.Security.Rootless}}"], capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return {"available": False, "reason": "podman info did not answer within 15 s"}
    if q.returncode != 0:
        return {"available": False, "reason": "podman info failed for this user"}
    if q.stdout.strip() != "true":
        return {"available": False, "reason": "podman is not running rootless for this user (AegisLab never runs containers as root)"}
    try:
        env = runtime.environment()
    except Exception:  # noqa: BLE001 - any failure of the runtime query means live mode is unavailable
        return {"available": False, "reason": "podman info output could not be read"}
    try:
        image = subprocess.run(["podman", "image", "exists", runtime.IMAGE], capture_output=True, timeout=15).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        image = False
    out = {"available": image, "rootless": True, "image": runtime.IMAGE, "image_present": image,
           **{k: env.get(k) for k in ("podman", "oci_runtime", "oci_runtime_version", "selinux", "cgroups", "kernel", "cpus",
                                      "cpuset_delegated", "seccomp_profile")}}
    if not image:
        out["reason"] = "sandbox image %s is not built yet (scripts/start_prototype.sh builds it)" % runtime.IMAGE
    return out


def _model_status() -> dict:
    try:
        d = model_client.load_config().describe()
    except model_client.ModelBackendError:
        return {"backend": "invalid", "label": "MODEL BACKEND MISCONFIGURED", "detail": "AEGIS_MODEL_* settings are invalid; runs refuse to freeze"}
    if d.get("backend", "stub") == "stub":
        return {"backend": "stub", "label": "STUB MODEL", "detail": "deterministic stub model worker in a fresh container per run; not an LLM"}
    return {"backend": d.get("backend"), "label": "REAL MODEL (OpenAI-compatible endpoint)", "detail": "model %s; server-side state is outside AegisLab's control" % d.get("model")}


def _lab_runs() -> list:
    base = store.p("runs")
    if not base.exists():
        return []
    return sorted(d.name for d in base.iterdir() if d.is_dir() and LAB_RUN_RE.fullmatch(d.name))


def _signed_upto(run_id) -> int:
    v = read_jsonl(store.vault_path(run_id))
    return max((c.get("seq", 0) for c in v), default=0)


@app.get("/api/lab/status")
def status():
    podman = _cached("podman", 20, _podman_status)
    rec_all = runs.list_runs()
    latest = api.public_view(rec_all[0]) if rec_all else None
    integrity = None
    terminal = next((r for r in rec_all if r.get("state") in ("RELEASED", "FAILED")), None)
    if terminal:
        v = runs.verify_run(terminal["id"])
        integrity = {"run_id": terminal["id"], "state": terminal["state"], "ok": v["ok"], "terminal_verified": v["terminal_verified"],
                     "entries": v["entries"], "checkpoints_checked": v["checkpoints_checked"], "findings": [f["issue"] for f in v["findings"]][:5],
                     "checked_against": v.get("checked_against")}
    ref = _bundles().get("DEMO-001-RELEASED")
    shipped = _shipped_status(ref) if ref else {}
    return {
        "control_plane": {"ok": True, "service": "aegislab-control-plane", "console": "r1"},
        "mode": "live" if podman.get("available") else "degraded",
        "mode_reason": None if podman.get("available") else podman.get("reason"),
        "demo_identities": os.environ.get("AEGIS_DEMO_MODE") == "1",
        "identity_model": "operator session (loopback launch link, HttpOnly cookie, CSRF token); role tokens stay on the server",
        "execution_modes": {"live": "LIVE SANDBOX / STUB MODEL" if podman.get("available") else "UNAVAILABLE",
                            "replay": "REPLAY / RECORDED", "experiments": "PRECOMPUTED REAL-MODEL"},
        "state_dir": _rel(store.VAR),
        "podman": podman,
        "model": _model_status(),
        "hardening_flags": {r: runtime.hardening_flags(r) for r in ("red", "blue", "model")},
        "runs": {"total": len(rec_all), "lab": len(_lab_runs()), "latest": latest,
                 "active": [r["id"] for r in rec_all if r.get("state") == "RUNNING"]},
        "integrity_latest_terminal_run": integrity,
        "integrity_shipped_bundle": {"bundle": "DEMO-001-RELEASED", "exit_code": shipped.get("exit_code"),
                                     "ok": (shipped.get("result") or {}).get("ok"),
                                     "terminal_verified": (shipped.get("result") or {}).get("terminal_verified")},
        "code_revision": _cached("revision", 3600, _code_revision),
        "generated_at": time.time(),
    }


def _shipped_status(ref) -> dict:
    """Verification of the shipped bundle for the status page, cached for an hour, but only once it is conclusive: a busy
    verifier slot or a timeout is reported as unknown now and retried on the next status request."""
    with _cache_lock:
        hit = _cache.get("shipped-verify")
    if hit and time.monotonic() - hit[0] < 3600:
        return hit[1]
    res = _verify_bundle(ref, quiet=True)
    if res.get("exit_code") is not None:
        with _cache_lock:
            _cache["shipped-verify"] = (time.monotonic(), res)
    return res


def _code_revision():
    sys.path.insert(0, str(ROOT / "evaluation"))
    try:
        import revision
        return revision.code_revision()
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------------------------------------ live evaluation run
class PrepareReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timing_bucket_ms: int = 250
    defence_profile: str | None = None
    stop_after: Literal["created", "started"] = "started"


class ProfileReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str


def _client() -> TestClient:
    """In-process client for the unchanged control plane: requests go through the same handlers, role checks and gates."""
    return TestClient(api.app, raise_server_exceptions=False, base_url="http://127.0.0.1")


def _require_live():
    st = _cached("podman", 20, _podman_status)
    if not st.get("available"):
        raise HTTPException(503, "live execution unavailable: %s. The evidence centre and the replay recording still work." % st.get("reason"))


# Fixed, reviewed blue-team configurations. The browser chooses a key; the rules themselves never leave the server and are
# never shown to the red side. "none" is a control: without rules the stub model's unsafe completions reach red.
def _sample_defence():
    return json.loads((ROOT / "samples" / "defence_config.json").read_text())


DEFENCE_PROFILES = {
    "sample": {"title": "Sample defence blue-v1.3 (default)", "rules": "3 input patterns, 1 output pattern",
               "summary": "The shipped sample configuration: blocks the obvious jailbreak phrasings and the stub model's unsafe marker.",
               "config": _sample_defence},
    "hardened": {"title": "Hardened defence (lab)", "rules": "9 input patterns, 2 output patterns",
                 "summary": "The sample rules plus obfuscated and guideline-override phrasings, canary planting, and an output rule for canary-shaped tokens.",
                 "config": lambda: {"version": "lab-hardened-1", "_note": "AegisLab console lab profile (synthetic).",
                                    "input_patterns": _sample_defence()["input_patterns"] + [
                                        "disregard (your )?guidelines", "no rules", "1gnore", "bypass", "remember this", "canary"],
                                    "output_patterns": ["\\[UNSAFE-MARKER\\]", "CANARY-[0-9a-f]{12}"]}},
    "none": {"title": "No defence (control)", "rules": "0 patterns",
             "summary": "A negative control: the defence runner allows everything, so the outcome counts show what the defence normally stops.",
             "config": lambda: {"version": "lab-none", "_note": "AegisLab console negative control (synthetic).",
                                "input_patterns": [], "output_patterns": []}},
}


def _lab_meta(run_id) -> dict:
    """Unsigned convenience notes the console keeps per lab run (which profile was chosen). The signed record is the audit log."""
    return store.read_json(store.p("lab", "runs", run_id + ".json")) or {}


def _api_step(actor, method, path, body=None) -> dict:
    """One real control-plane request with the server-held token of `actor`. Raises on anything but HTTP 200."""
    r = _client().request(method, path, json=body, headers={"X-Aegis-Token": store.tokens()[actor]})
    step = {"actor": actor, "action": "%s %s" % (method, path), "status": r.status_code, "detail": _detail(r)}
    if r.status_code != 200:
        raise HTTPException(502 if r.status_code >= 500 else r.status_code,
                            "%s %s as %s failed with HTTP %d: %s" % (method, path, actor, r.status_code, _detail(r)))
    return step


def _apply_profile(run_id, profile) -> dict:
    step = _api_step("blue_participant", "POST", "/api/runs/%s/defence-config" % run_id, DEFENCE_PROFILES[profile]["config"]())
    store.write_json(store.p("lab", "runs", run_id + ".json"), dict(_lab_meta(run_id), defence_profile=profile))
    return step


@app.get("/api/lab/defence-profiles")
def defence_profiles():
    return [{"id": k, **{f: v[f] for f in ("title", "rules", "summary")}} for k, v in DEFENCE_PROFILES.items()]


IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
_created = {}  # (caller, idempotency key) -> response of the create request that used it (bounded, this process only)


@app.post("/api/lab/runs")
def prepare_run(req: PrepareReq, request: Request, x_aegis_token: str | None = Header(None),
                x_aegis_idempotency_key: str | None = Header(None)):
    """Create a new evaluation run LAB-nnn through the real API, optionally with a defence profile. With stop_after="started"
    (the R1 behaviour) it is also frozen and started; the broker then runs the red sandbox, defence runner and model worker
    in real rootless containers in the background. The console UI uses stop_after="created" and the per-step endpoints.

    X-Aegis-Idempotency-Key (Phase R3, optional): a retried or duplicated request with the same key and the same caller gets
    the original answer with replayed=true instead of creating a second run (the UI sends one key per click)."""
    who = _authorize(request, x_aegis_token, "operator")
    key = None
    if x_aegis_idempotency_key is not None:
        if not IDEMPOTENCY_RE.fullmatch(x_aegis_idempotency_key):
            raise HTTPException(422, "X-Aegis-Idempotency-Key must be 8-64 characters of A-Z a-z 0-9 _ -")
        key = (who["via"], x_aegis_token or request.cookies.get(lab_session.COOKIE), x_aegis_idempotency_key)
    if req.timing_bucket_ms not in (0, 250):
        raise HTTPException(422, "timing_bucket_ms must be 0 or 250")
    if req.defence_profile is not None and req.defence_profile not in DEFENCE_PROFILES:
        raise HTTPException(422, "unknown defence profile")
    _require_live()
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "another lab action is in progress")
    try:
        if key and key in _created:
            prior = _created[key]
            return dict(prior, replayed=True, state=runs.Run(prior["run_id"]).state, run=_run_view(prior["run_id"]))
        existing = _lab_runs()
        if len(existing) >= MAX_LAB_RUNS:
            raise HTTPException(409, "lab run limit (%d) reached; restart with scripts/start_prototype.sh --reset" % MAX_LAB_RUNS)
        active = [r for r in existing if runs.Run(r).state == "RUNNING"]
        if active:
            raise HTTPException(409, "run %s is still executing; wait for it to seal" % active[0])
        run_id = "LAB-%03d" % (max((int(r[4:]) for r in existing), default=0) + 1)
        steps = [_api_step("operator", "POST", "/api/runs", {"run_id": run_id, "timing_bucket_ms": req.timing_bucket_ms, "tags": ["lab", "console"]})]
        if req.defence_profile:
            steps.append(_apply_profile(run_id, req.defence_profile))
        if req.stop_after == "started":
            steps.append(_api_step("operator", "POST", "/api/runs/%s/freeze" % run_id))
            steps.append(_api_step("operator", "POST", "/api/runs/%s/start" % run_id))
            _journal("prepare", run_id, "STARTED", "operator created, froze and started %s" % run_id)
        else:
            _journal("create", run_id, "CREATED", "operator created %s" % run_id)
        if key:
            while len(_created) >= 256:
                del _created[next(iter(_created))]
            _created[key] = {"run_id": run_id, "steps": steps}
        return {"run_id": run_id, "steps": steps, "state": runs.Run(run_id).state, "run": _run_view(run_id), "replayed": False}
    finally:
        _lab_lock.release()


def _lab_step(request, token, run_id, fn):
    """Run one lifecycle step on an existing lab run under the lab lock; return the step record and the new run view."""
    _authorize(request, token, "operator")
    _lab_run(run_id, None)
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "another lab action is in progress")
    try:
        step = fn()
    finally:
        _lab_lock.release()
    return {"run_id": run_id, "step": step, "state": runs.Run(run_id).state, "run": _run_view(run_id)}


@app.post("/api/lab/runs/{run_id}/defence")
def configure_defence(run_id: str, req: ProfileReq, request: Request, x_aegis_token: str | None = Header(None)):
    """Submit a fixed defence profile as the blue participant. The control plane accepts it only while the run is CREATED."""
    if req.profile not in DEFENCE_PROFILES:
        raise HTTPException(422, "unknown defence profile")
    res = _lab_step(request, x_aegis_token, run_id, lambda: _apply_profile(run_id, req.profile))
    _journal("defence", run_id, "CONFIGURED", "blue participant submitted profile %s" % req.profile)
    return res


@app.post("/api/lab/runs/{run_id}/freeze")
def freeze_run(run_id: str, request: Request, x_aegis_token: str | None = Header(None)):
    _authorize(request, x_aegis_token, "operator")  # authorisation first: an unauthenticated caller learns nothing about the host
    _require_live()  # freezing records the sandbox image digest and the host environment
    res = _lab_step(request, x_aegis_token, run_id, lambda: _api_step("operator", "POST", "/api/runs/%s/freeze" % run_id))
    _journal("freeze", run_id, "FROZEN", "operator froze %s" % run_id)
    return res


@app.post("/api/lab/runs/{run_id}/start")
def start_run(run_id: str, request: Request, x_aegis_token: str | None = Header(None)):
    _authorize(request, x_aegis_token, "operator")
    _require_live()

    def go():
        active = [r for r in _lab_runs() if r != run_id and runs.Run(r).state == "RUNNING"]
        if active:
            raise HTTPException(409, "run %s is still executing; wait for it to seal" % active[0])
        return _api_step("operator", "POST", "/api/runs/%s/start" % run_id)
    res = _lab_step(request, x_aegis_token, run_id, go)
    _journal("start", run_id, "STARTED", "operator started %s" % run_id)
    return res


NEXT = {
    "CREATED": [("defence", "Configure the defence (blue participant)"), ("freeze", "Freeze the configuration (operator)")],
    "FROZEN": [("start", "Start the run (operator)")],
    "RUNNING": [("wait", "Wait: the broker is executing the run in containers")],
    "SEALED": [("scenarios", "Run the denial scenarios against the sealed results"), ("release", "Release as the reviewer")],
    "RELEASED": [("verify", "Verify the exported bundle"), ("tamper", "Tamper with a disposable copy")],
    "FAILED": [("new", "Start a new run: a failed run is never releasable")],
}


def _run_view(run_id) -> dict:
    run = runs.Run(run_id)
    rec = run.record
    mon = read_jsonl(run.dir / "monitor.jsonl")
    last = mon[-1] if mon else None
    return {"run": api.public_view(rec), "mode": "LIVE SANDBOX / STUB MODEL", "defence_profile": _lab_meta(run_id).get("defence_profile"),
            "events": len(mon), "audit_entries": run.audit.seq, "signed_upto": _signed_upto(run_id),
            "last_event": {k: last.get(k) for k in ("seq", "ts", "type", "actor", "summary", "decision")} if last else None,
            "bundle_exported": store.p("bundles", run_id).is_dir(),
            "next_actions": [{"id": a, "label": t} for a, t in NEXT.get(rec.get("state"), [])]}


@app.get("/api/lab/runs/{run_id}")
def lab_run_view(run_id: str):
    """Public view of a lab run (same fields as GET /api/runs/{id} for an observer) plus lifecycle helpers."""
    _lab_run(run_id, None)
    return _run_view(run_id)


# ------------------------------------------------------------------------------------------------ interrupted runs
def _recover_interrupted():
    """A run whose broker thread died with a previous console process would stay RUNNING for ever. Mark it FAILED the way the
    broker fails closed (run.failed, then a signed terminal checkpoint) and remove its containers. Called at startup."""
    alive = {t.name for t in threading.enumerate()}
    for rid in _lab_runs():
        run = runs.Run(rid)
        if run.state != "RUNNING" or "broker-" + rid in alive:
            continue
        for role in ("red", "blue", "model"):
            try:
                runtime.stop("aegis-%s-%s" % (rid.lower(), role))
            except Exception:  # noqa: BLE001 - no Podman: nothing to clean up
                pass
        with run.lifecycle():
            if run.state != "RUNNING":
                continue
            run.log("run.failed", "control-plane", {"error": "Interrupted", "detail": "the console stopped while the run was executing"},
                    monitor={"summary": "Run failed closed: interrupted by a console restart", "decision": "failed"},
                    checkpoint=False, close=True)
            run.update(state="FAILED")
            run.terminal_checkpoint("FAILED")
        _journal("recover", rid, "FAILED", "marked FAILED after an interrupted execution")


def _detail(r):
    try:
        b = r.json()
    except ValueError:
        return None
    return b.get("detail") if isinstance(b, dict) and "detail" in b else None


# ------------------------------------------------------------------------------------------------ scenarios
class ScenarioReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str | None = None


SCENARIOS = {
    "prohibited-access": {
        "title": "Prohibited access to sealed results",
        "needs": "SEALED",
        "summary": "The red participant tries to read the sealed attack artifacts and to release the run; an anonymous caller "
                   "tries the same read. The control plane must refuse each request, record the refusal in the hash-chained "
                   "audit log, leave the run SEALED and return no protected value.",
        "expected": "3 refusals (HTTP 403), 3 new policy.denied audit entries, state still SEALED, 0 protected values in any response",
    },
    "cross-role-isolation": {
        "title": "Cross-role isolation (API and sandbox)",
        "needs": "SEALED",
        "summary": "The blue participant tries to read red's sealed payloads and sees the run without the secret digests a reviewer "
                   "sees; a forged token is rejected. Then the five forbidden requests the red sandbox itself sent through its "
                   "mailbox during the run are read back from the redacted monitoring stream.",
        "expected": "blue read refused (403) and logged, digests hidden from blue but shown to the reviewer, forged token 401, "
                    "5 broker denials of the red sandbox, 0 protected values in any response",
    },
    "authorized-release": {
        "title": "Authorised release by the reviewer",
        "needs": "SEALED",
        "summary": "The reviewer, the only role allowed to release, releases the sealed run. The release verifies the audit chain "
                   "and the attack commitments first, writes the run.released event, signs the terminal checkpoint and exports "
                   "the reviewer bundle. Afterwards the reviewer may read the artifacts.",
        "expected": "release HTTP 200, state RELEASED, run.released by reviewer in the audit log, strict verification ok with a "
                    "terminal checkpoint, artifacts readable by the reviewer, bundle exported",
    },
    "sandbox-containment": {
        "title": "Sandbox containment (live rootless container)",
        "needs": None,
        "summary": "A fresh container with exactly the red sandbox's hardening flags runs a fixed probe: network connections, DNS, "
                   "writes to the root filesystem, capabilities, foreign paths, and an attack on its own mailbox (symlink and FIFO "
                   "at the broker's temporary names, renaming the mailbox). The broker's real write routine then replies into that mailbox.",
        "expected": "every connection and write refused, CapEff 0, NoNewPrivs 1, seccomp filter on, foreign paths absent, broker "
                    "replies delivered as regular files, victim file intact, broker not blocked",
    },
}


def _audit_since(run_id, seq):
    return [e for e in read_jsonl(store.run_dir(run_id) / "audit.jsonl") if e["seq"] > seq]


def _public_entry(e, signed_upto):
    """Fields of an audit entry that are safe to show: lifecycle and refusal metadata only, never a payload or output."""
    data = e.get("data") or {}
    keep = {k: data[k] for k in ("op", "reason", "audit_entries_verified", "commitments_verified") if k in data}
    return {"seq": e["seq"], "ts": e["ts"], "type": e["type"], "actor": e["actor"], "data": keep, "hash": e["hash"], "prev": e["prev"],
            "signed": e["seq"] <= signed_upto}


def _protected_markers(run_id) -> list:
    d = store.run_dir(run_id)
    marks = [(store.read_json(d / "sealed/canary.json") or {}).get("canary")]
    for a in (store.read_json(d / "private/red/attack_pack.json") or {}).get("attacks", []):
        marks.append(a.get("payload"))
    for a in read_jsonl(d / "sealed/artifacts.jsonl"):
        marks.append(a.get("model_output"))
    marks.extend(store.tokens().values())
    marks.append("-----BEGIN")
    return [m for m in marks if isinstance(m, str) and len(m) >= 8]


def _scan(texts, markers):
    blob = "\n".join(texts)
    return sum(1 for m in markers if m in blob)


class _Steps:
    def __init__(self):
        self.steps, self.bodies, self.error = [], [], None

    def call(self, c, actor, method, path, token, expect, explain, audit=None, run_id=None):
        """One real API call. expect: the HTTP status the policy requires. audit: (type, op) of the audit entry it must create."""
        pre = read_jsonl(store.run_dir(run_id) / "audit.jsonl")[-1]["seq"] if run_id else 0
        headers = {"X-Aegis-Token": token} if token else {}
        r = c.request(method, path, headers=headers)
        self.bodies.append(r.text)
        step = {"actor": actor, "action": "%s %s" % (method, path), "expected_status": expect, "status": r.status_code,
                "detail": _detail(r), "explain": explain, "decision": "allowed" if r.status_code < 300 else "denied" if r.status_code < 500 else "error"}
        if r.status_code >= 500:
            self.error = "%s %s returned HTTP %d (backend failure, not a security decision)" % (method, path, r.status_code)
        ok = r.status_code == expect
        if audit and run_id:
            new = [e for e in _audit_since(run_id, pre) if e["type"] == audit[0] and (audit[1] is None or (e.get("data") or {}).get("op") == audit[1])]
            step["audit"] = _public_entry(new[0], _signed_upto(run_id)) if new else None
            if not new:
                step["audit_missing"] = "expected a %s audit entry%s" % (audit[0], " for op %s" % audit[1] if audit[1] else "")
            ok = ok and bool(new)
        step["ok"] = ok
        self.steps.append(step)
        return r


def _lab_run(run_id, needs):
    if not run_id or not LAB_RUN_RE.fullmatch(run_id) or not store.run_dir(run_id).is_dir():
        raise HTTPException(404, "unknown lab run; start one first")
    st = runs.Run(run_id).state
    if needs and st != needs:
        raise HTTPException(409, "this scenario needs a %s run; %s is %s" % (needs, run_id, st))
    return run_id


@app.get("/api/lab/scenarios")
def list_scenarios():
    return [{"id": k, **v} for k, v in SCENARIOS.items()]


@app.post("/api/lab/scenarios/{sid}/run")
def run_scenario(sid: str, req: ScenarioReq, request: Request, x_aegis_token: str | None = Header(None)):
    if sid not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    _authorize(request, x_aegis_token, "operator")
    meta = SCENARIOS[sid]
    if sid == "sandbox-containment":
        _require_live()
    run_id = _lab_run(req.run_id, meta["needs"]) if meta["needs"] else None
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "another lab action is in progress")
    t0 = time.time()
    try:
        res = {"prohibited-access": _s_prohibited, "cross-role-isolation": _s_isolation,
               "authorized-release": _s_release, "sandbox-containment": _s_containment}[sid](run_id)
    finally:
        _lab_lock.release()
    res.update({"scenario": sid, "title": meta["title"], "expected": meta["expected"], "run_id": run_id, "mode": "LIVE",
                "started_at": t0, "finished_at": time.time()})
    if res.get("error"):
        res["verdict"] = "ERROR"
    else:
        res["verdict"] = "PASS" if all(s["ok"] for s in res["steps"]) and all(c["ok"] for c in res["checks"]) else "FAIL"
    _journal(sid, run_id, res["verdict"], meta["title"])
    _save_result(sid, res)
    return res


def _s_prohibited(run_id):
    tok, c, s = store.tokens(), _client(), _Steps()
    base = "/api/runs/%s" % run_id
    s.call(c, "red_participant", "GET", base + "/artifacts", tok["red_participant"], 403,
           "Artifacts hold red's payloads and the model outputs. They stay sealed until a reviewer releases the run; the result gate refuses every other role.",
           audit=("policy.denied", "read_artifacts"), run_id=run_id)
    s.call(c, "red_participant", "POST", base + "/release", tok["red_participant"], 403,
           "Only an authorised reviewer can release results. A participant cannot open the gate on its own run.",
           audit=("policy.denied", "release"), run_id=run_id)
    s.call(c, "observer (no token)", "GET", base + "/artifacts", None, 403,
           "A caller without an identity is an observer. Observers see the redacted monitoring stream only.",
           audit=("policy.denied", "read_artifacts"), run_id=run_id)
    markers = _protected_markers(run_id)
    hits = _scan(s.bodies, markers)
    return {"steps": s.steps, "error": s.error, "checks": [
        {"label": "run is still SEALED after the attempts", "ok": runs.Run(run_id).state == "SEALED", "found": runs.Run(run_id).state},
        {"label": "protected values in the responses (%d markers: canary, payloads, model outputs, tokens, key header)" % len(markers), "ok": hits == 0,
         "found": "%d of %d markers found" % (hits, len(markers))},
    ]}


def _s_isolation(run_id):
    tok, c, s = store.tokens(), _client(), _Steps()
    base = "/api/runs/%s" % run_id
    s.call(c, "blue_participant", "GET", base + "/artifacts", tok["blue_participant"], 403,
           "Blue must not see red's payloads before release; otherwise it could tune its defence to the attack set.",
           audit=("policy.denied", "read_artifacts"), run_id=run_id)
    rb = s.call(c, "blue_participant", "GET", base, tok["blue_participant"], 200,
                "Blue may see the run, but not the digests of the frozen configuration and attack pack: a digest of a guessable file is a confirmation oracle.")
    rr = s.call(c, "reviewer", "GET", base, tok["reviewer"], 200, "The reviewer is entitled to the digests before release.")
    s.call(c, "forged identity", "GET", base + "/evidence", "forged-" + secrets.token_hex(8), 401,
           "Identities are checked server-side with a constant-time comparison against issued tokens; an unknown token is rejected outright.")
    blue_m = ((rb.json() or {}).get("manifest") or {}) if rb.status_code == 200 else {}
    rev_m = ((rr.json() or {}).get("manifest") or {}) if rr.status_code == 200 else {}
    secret = ("defence_config_digest", "attack_pack_digest")
    broker_denials = [e for e in read_jsonl(store.run_dir(run_id) / "monitor.jsonl") if e.get("type") == "policy.denied" and e.get("actor") == "broker"]
    signed = _signed_upto(run_id)
    markers = _protected_markers(run_id)
    hits = _scan(s.bodies, markers)
    return {"steps": s.steps, "error": s.error,
            "sandbox_denials": [{"seq": e.get("seq"), "summary": e.get("summary"), "signed": (e.get("seq") or 0) <= signed} for e in broker_denials],
            "checks": [
                {"label": "secret digests absent from blue's view", "ok": not any(k in blue_m for k in secret), "found": "absent" if not any(k in blue_m for k in secret) else "PRESENT"},
                {"label": "secret digests present in the reviewer's view", "ok": all(rev_m.get(k) for k in secret),
                 "found": ", ".join("%s %s…" % (k.split("_")[0], str(rev_m.get(k, ""))[7:19]) for k in secret)},
                {"label": "forbidden mailbox requests from the red sandbox denied by the broker during the run", "ok": len(broker_denials) == 5,
                 "found": "%d denials, %d covered by a signed checkpoint" % (len(broker_denials), sum((e.get("seq") or 0) <= signed for e in broker_denials))},
                {"label": "protected values in the responses", "ok": hits == 0, "found": "%d of %d markers found" % (hits, len(markers))},
            ]}


def _s_release(run_id):
    tok, c, s = store.tokens(), _client(), _Steps()
    base = "/api/runs/%s" % run_id
    r = s.call(c, "reviewer", "POST", base + "/release", tok["reviewer"], 200,
               "The reviewer holds the release right. Before releasing, the gate re-verifies the audit chain against the reviewer vault and "
               "checks every revealed attack against its commitment; then it logs run.released and signs the terminal checkpoint.",
               audit=("run.released", None), run_id=run_id)
    rel = r.json() if r.status_code == 200 else {}
    s.call(c, "reviewer", "GET", base + "/artifacts", tok["reviewer"], 200,
           "After release the reviewer (and the participants) may read the artifacts; the observer still may not.")
    arts = len(read_jsonl(store.run_dir(run_id) / "sealed/artifacts.jsonl"))
    v = runs.verify_run(run_id)
    bundle = store.p("bundles", run_id)
    exported, export_err = False, None
    if s.steps[0]["ok"]:
        try:
            if not bundle.exists():
                evidence.export_bundle(run_id, bundle)
            exported = True
        except (ValueError, OSError) as exc:
            export_err = type(exc).__name__
    return {"steps": s.steps, "error": s.error, "terminal_hash": rel.get("terminal_hash"),
            "commitments": rel.get("commitments"),
            "checks": [
                {"label": "run state is RELEASED", "ok": runs.Run(run_id).state == "RELEASED", "found": runs.Run(run_id).state},
                {"label": "strict verification: chain, signed checkpoints and terminal checkpoint", "ok": v["ok"] and v["terminal_verified"],
                 "found": "ok=%s, terminal_verified=%s, %d entries, %d checkpoints" % (v["ok"], v["terminal_verified"], v["entries"], v["checkpoints_checked"])},
                {"label": "attack commitments verified at release", "ok": bool(rel.get("commitments")) and rel["commitments"]["verified"] == rel["commitments"]["revealed"],
                 "found": "%s of %s revealed" % ((rel.get("commitments") or {}).get("verified"), (rel.get("commitments") or {}).get("revealed"))},
                {"label": "artifacts readable by the reviewer after release (count only shown here)", "ok": s.steps[1]["ok"], "found": "%d artifacts" % arts},
                {"label": "reviewer bundle exported for the evidence centre", "ok": exported, "found": _rel(bundle) if exported else export_err or "not exported"},
            ]}


PROBE_CODE = r'''
import json, os, socket
r = {"net": {}, "paths": {}, "mailbox": {}}
def attempt(group, name, fn):
    try:
        fn(); r[group][name] = "succeeded"
    except OSError as e:
        r[group][name] = "refused (errno %d)" % e.errno
for host, port in (("1.1.1.1", 53), ("10.0.2.2", 8400), ("127.0.0.1", 8400)):
    attempt("net", "tcp %s:%d" % (host, port), lambda h=host, p=port: socket.create_connection((h, p), timeout=2).close())
attempt("net", "dns example.com", lambda: socket.getaddrinfo("example.com", 443))
attempt("paths", "write /usr (root filesystem)", lambda: open("/usr/aegis-probe", "w").close())
for p in ("/aegis/frozen", "/aegis/sealed", "/aegis/private", "/aegis/spool/blue", "/aegis/spool/model", "/var/lib/aegis"):
    r["paths"][p] = "visible" if os.path.exists(p) else "absent"
r["uid"] = os.getuid()
r["proc"] = {l.split(":")[0]: l.split(":", 1)[1].strip() for l in open("/proc/self/status") if l.split(":")[0] in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp")}
attempt("mailbox", "plant symlink at the broker's next temp name", lambda: os.symlink("../../../audit.jsonl", "/aegis/spool/in/.000002.json.tmp"))
attempt("mailbox", "plant FIFO at a guessed temp name", lambda: os.mkfifo("/aegis/spool/in/.000003.json.tmp"))
attempt("mailbox", "rename the mailbox directory", lambda: os.rename("/aegis/spool/in", "/aegis/spool/in_moved"))
attempt("mailbox", "remove the mailbox directory", lambda: os.rmdir("/aegis/spool/in"))
print(json.dumps(r))
'''


def _s_containment(_run_id):
    work = Path(tempfile.mkdtemp(prefix="probe-", dir=_mk(store.p("lab"))))
    name = "aegis-lab-probe-" + secrets.token_hex(4)
    try:
        base = work / "run" / "spool" / "red"
        (base / "in").mkdir(parents=True)
        (base / "out").mkdir()
        marker = "AEGISLAB-PROBE-VICTIM-MUST-SURVIVE\n"
        victim = work / "run" / "audit.jsonl"
        victim.write_text(marker)
        args = ["podman", "run", "--rm", "--name", name, "--label", "aegislab=1"] + runtime.hardening_flags("red")
        for h, ctr, _m in runs.Broker._spool_mounts(base):
            args += ["-v", "%s:%s:Z" % (h, ctr)]
        args += [runtime.IMAGE, "python", "-c", PROBE_CODE]
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=PROBE_TIMEOUT_S)
            obs = json.loads(p.stdout)
        except subprocess.TimeoutExpired:
            subprocess.run(["podman", "rm", "-f", "-t", "0", name], capture_output=True)
            return {"steps": [], "checks": [], "error": "probe container did not finish within %d s" % PROBE_TIMEOUT_S}
        except ValueError:
            return {"steps": [], "checks": [], "error": "probe container produced no result (exit %d)" % p.returncode}
        t = time.monotonic()
        for n in ("000002.json", "000003.json"):  # the broker's real mailbox write path, onto the planted symlink and FIFO names
            runs._write_msg(base / "in", n, {"ok": False, "denied": True, "reason": "probe"})
        took = time.monotonic() - t
        delivered = sorted(q.name for q in (base / "in").iterdir() if q.is_file() and not q.is_symlink() and not q.name.startswith("."))
        outside = sorted(q.name for q in (work / "run").iterdir() if q.name not in ("spool", "audit.jsonl"))
        intact = victim.read_text() == marker and not outside
    finally:
        shutil.rmtree(work, ignore_errors=True)
    net_ok = all(v.startswith("refused") for v in obs["net"].values())
    proc = obs.get("proc", {})
    steps = [{"actor": "red sandbox (probe)", "action": k, "expected_status": "refused", "status": v, "decision": "denied" if v.startswith("refused") else "allowed",
              "ok": v.startswith("refused"), "explain": "--network none: the container has a loopback interface only"} for k, v in obs["net"].items()]
    steps += [{"actor": "red sandbox (probe)", "action": k, "expected_status": "refused" if "write" in k else "absent", "status": v,
               "decision": "denied" if v.startswith(("refused", "absent")) else "allowed", "ok": v.startswith(("refused", "absent")),
               "explain": "--read-only root filesystem" if "write" in k else "only the sandbox's own mailbox and private inputs are mounted"} for k, v in obs["paths"].items()]
    steps += [{"actor": "red sandbox (probe)", "action": k, "expected_status": "refused or harmless", "status": v,
               "decision": "denied" if v.startswith("refused") else "attempted", "ok": True,
               "explain": "the mailbox directories are separate bind mounts (cannot be moved); planted entries are handled by the broker below"}
              for k, v in obs["mailbox"].items()]
    return {"steps": steps, "error": None, "hardening_flags": runtime.hardening_flags("red"), "observed": obs, "checks": [
        {"label": "no network: every TCP connection and DNS lookup failed", "ok": net_ok, "found": "%d of %d refused" % (sum(v.startswith("refused") for v in obs["net"].values()), len(obs["net"]))},
        {"label": "no capabilities (CapEff 0)", "ok": proc.get("CapEff") == "0000000000000000", "found": proc.get("CapEff")},
        {"label": "no-new-privileges set", "ok": proc.get("NoNewPrivs") == "1", "found": proc.get("NoNewPrivs")},
        {"label": "seccomp filter active (mode 2)", "ok": proc.get("Seccomp") == "2", "found": proc.get("Seccomp")},
        {"label": "not root inside the container", "ok": obs.get("uid") != 0, "found": "uid %s" % obs.get("uid")},
        {"label": "broker replies delivered as regular files despite the planted symlink and FIFO", "ok": delivered == ["000002.json", "000003.json"], "found": ", ".join(delivered) or "none"},
        {"label": "victim file outside the mailbox intact and nothing created beside it (symlink not followed)", "ok": intact,
         "found": "intact" if intact else "MODIFIED or extra files: %s" % ", ".join(outside)},
        {"label": "broker did not block on the FIFO", "ok": took < 2.0, "found": "%.3f s for two writes" % took},
    ]}


def _mk(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


# ------------------------------------------------------------------------------------------------ lab journal (unsigned)
def _journal(kind, run_id, verdict, title):
    store.append_jsonl(store.p("lab", "journal.jsonl"), {"ts": round(time.time(), 3), "kind": kind, "run_id": run_id, "verdict": verdict, "title": title})


@app.get("/api/lab/journal")
def journal():
    return read_jsonl(store.p("lab", "journal.jsonl"))[-50:][::-1]


# ------------------------------------------------------------------------------------------------ recorded results (unsigned)
MAX_RESULTS = 200


_results_lock = threading.Lock()  # tamper demonstrations run outside the lab lock; numbering must not collide


def _save_result(sid, res):
    """Keep the full result of a scenario or tamper demonstration so the UI can show it after a reload and the graph can mark
    the boundary it exercised. Results hold only what the scenario already returned (scanned for protected values)."""
    d = store.p("lab", "results")
    with _results_lock:
        d.mkdir(parents=True, exist_ok=True)
        files = sorted(d.glob("*.json"))
        n = int(files[-1].name[:5]) + 1 if files else 1
        store.write_json(d / ("%05d-%s.json" % (n, re.sub(r"[^a-z0-9-]", "", sid)[:40])), dict(res, result_id=n))
        for old in files[:max(0, len(files) + 1 - MAX_RESULTS)]:
            old.unlink(missing_ok=True)


@app.get("/api/lab/results")
def results(scenario: str | None = None, limit: int = 20):
    """Most recent recorded results, newest first (bounded)."""
    limit = max(1, min(limit, 50))
    d = store.p("lab", "results")
    out = []
    for f in sorted(d.glob("*.json"), reverse=True) if d.is_dir() else []:
        r = store.read_json(f)
        if r and (scenario is None or r.get("scenario") == scenario):
            out.append(r)
            if len(out) >= limit:
                break
    return out


# ------------------------------------------------------------------------------------------------ signed audit log (metadata)
AUDIT_SAFE = ("op", "reason", "tenant", "complete", "evaluated", "attack_count", "count", "commitments_verified", "audit_entries_verified",
              "matches_manifest", "network_modes", "strategy", "action", "attack_id", "commitment_verified", "canary_leaks", "policy",
              "aborted", "model_backend_errors", "manifest_digest", "sandbox_image_id", "error", "where")
AUDIT_AFTER_RELEASE = ("outcome", "outcomes")
AUDIT_DECISION = {"policy.denied": "denied", "mailbox.violation": "denied", "run.failed": "failed", "run.released": "allowed",
                  "attack.evaluated": "allowed", "defence.attested": "ok"}


def _audit_view(e, signed_upto, released):
    """Metadata of one audit entry: lifecycle, actor, operation and refusal reason. Digests of team inputs, payloads, model
    outputs and defence rules are never included; attack outcomes only once the run is RELEASED."""
    data = e.get("data") or {}
    keep = {k: data[k] for k in AUDIT_SAFE + (AUDIT_AFTER_RELEASE if released else ()) if k in data}
    dec = AUDIT_DECISION.get(e["type"], "info")
    if e["type"] == "defence.attested" and not data.get("matches_manifest"):
        dec = "failed"
    return {"seq": e["seq"], "ts": e["ts"], "type": e["type"], "actor": e["actor"], "decision": dec, "data": keep,
            "hash": e["hash"], "prev": e["prev"], "signed": e["seq"] <= signed_upto}


@app.get("/api/lab/runs/{run_id}/audit")
def run_audit(run_id: str, request: Request, x_aegis_token: str | None = Header(None), offset: int = 0, limit: int = 200,
              type: str | None = None, actor: str | None = None, decision: str | None = None, order: Literal["asc", "desc"] = "asc"):
    """The run's hash-chained audit log, metadata only, for the operator session (or an operator / reviewer token).
    Server-side filters and bounded pagination; every row carries its sequence number, hash and signature coverage."""
    _authorize(request, x_aegis_token, "operator", "reviewer")
    _lab_run(run_id, None)
    run = runs.Run(run_id)
    offset, limit = max(0, offset), max(1, min(limit, 500))
    signed = _signed_upto(run_id)
    rows = [_audit_view(e, signed, run.state == "RELEASED") for e in read_jsonl(run.dir / "audit.jsonl")]
    total = len(rows)
    rows = [r for r in rows if (type is None or r["type"] == type) and (actor is None or r["actor"] == actor)
            and (decision is None or r["decision"] == decision)]
    if order == "desc":
        rows.reverse()
    return {"run_id": run_id, "state": run.state, "total": total, "matched": len(rows), "offset": offset, "limit": limit,
            "signed_upto": signed, "checkpoints": len(read_jsonl(store.vault_path(run_id))),
            "terminal_anchor": store.anchor_path(run_id).is_file(),
            "facets": {"type": sorted({e["type"] for e in read_jsonl(run.dir / "audit.jsonl")}),
                       "actor": sorted({e["actor"] for e in read_jsonl(run.dir / "audit.jsonl")})},
            "entries": rows[offset:offset + limit], "after_close": _after_close(run)}


def _post_terminal_view(e):
    data = e.get("data") or {}
    return {"ts": e.get("ts"), "type": e.get("type"), "actor": e.get("actor"), "data": {k: data[k] for k in ("op", "reason") if k in data},
            "signed": False}


def _after_close(run) -> dict:
    """What happened after the signed chain closed (Phase R3). The terminal checkpoint covers the chain up to the final
    lifecycle event and the chain is never reopened. Later events, typically refused requests against a released run, are
    kept by the control plane in post_terminal.jsonl: unsigned, informational, capped (runs.POST_TERMINAL_CAP), outside the
    evidence the verifier checks. Shown separately so they are never mistaken for signed entries."""
    rows = read_jsonl(run.dir / "post_terminal.jsonl")
    rec = run.record
    return {"closed": run.audit.closed, "recorded": len(rows), "seen": rec.get("post_terminal_events", len(rows)),
            "signed": False, "entries": [_post_terminal_view(e) for e in rows[-50:]][::-1],
            "note": "Recorded after the signed chain closed: unsigned, informational, not covered by the terminal checkpoint."}


# ------------------------------------------------------------------------------------------------ manual request probe
PROBE_OPS = {
    "detail": ("GET", "", "Read the run detail (are the secret digests shown?)"),
    "artifacts": ("GET", "/artifacts", "Read the sealed attack artifacts"),
    "evidence": ("GET", "/evidence", "Read the evidence report"),
    "verify": ("GET", "/verify", "Verify the audit log"),
    "release": ("POST", "/release", "Release the run"),
}
PROBE_ROLES = ("observer", "operator", "reviewer", "blue_participant", "red_participant", "forged")


class ProbeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str
    op: str
    run_id: str


def _shape(obj, depth=0):
    """The structure of a response, not its values: what a role received, without putting protected data in the browser."""
    if isinstance(obj, dict):
        return {k: (_shape(v, depth + 1) if depth < 1 else type(v).__name__) for k, v in list(obj.items())[:40]}
    if isinstance(obj, list):
        return "list of %d" % len(obj)
    if isinstance(obj, str):
        return "string (%d characters)" % len(obj)
    return type(obj).__name__ if obj is not None else None


@app.get("/api/lab/probe-ops")
def probe_ops():
    return {"ops": {k: {"method": m, "path": "/api/runs/{id}" + p, "title": t} for k, (m, p, t) in PROBE_OPS.items()}, "roles": PROBE_ROLES}


@app.post("/api/lab/probe")
def probe(req: ProbeReq, request: Request, x_aegis_token: str | None = Header(None)):
    """Send one allowlisted control-plane request as the chosen demonstration identity, server-side. The browser picks a role,
    an operation key and a lab run; it never sees a token. The response body is reduced to its shape and a leak count."""
    _authorize(request, x_aegis_token, "operator")
    if req.role not in PROBE_ROLES or req.op not in PROBE_OPS:
        raise HTTPException(422, "unknown role or operation")
    run_id = _lab_run(req.run_id, None)
    method, suffix, title = PROBE_OPS[req.op]
    token = None if req.role == "observer" else "forged-" + secrets.token_hex(8) if req.role == "forged" else store.tokens()[req.role]
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "another lab action is in progress")
    try:
        s = _Steps()
        pre = read_jsonl(store.run_dir(run_id) / "audit.jsonl")[-1]["seq"]
        pre_counts = _record_counts(run_id)
        r = s.call(_client(), req.role, method, "/api/runs/%s%s" % (run_id, suffix), token, None, title)
        new = _audit_since(run_id, pre)
        late = read_jsonl(store.run_dir(run_id) / "post_terminal.jsonl")[pre_counts["post_terminal"]:]
        recording = _recording(new, late, pre_counts, _record_counts(run_id))
        exported = _export_if_released(run_id) if req.op == "release" and r.status_code == 200 else None
    finally:
        _lab_lock.release()
    try:
        body = r.json()
    except ValueError:
        body = None
    leaks = _scan(s.bodies, _protected_markers(run_id))
    signed = _signed_upto(run_id)
    summary = None
    if r.status_code == 200 and req.op == "verify":
        summary = {k: body.get(k) for k in ("ok", "entries", "checkpoints_checked", "terminal_verified")}
    elif r.status_code == 200 and req.op == "detail":
        summary = {"state": body.get("state"), "manifest_fields": sorted((body.get("manifest") or {}).keys()),
                   "secret_digests_shown": [k for k in api.SECRET_DIGESTS if k in (body.get("manifest") or {})]}
    elif r.status_code == 200 and req.op == "artifacts":
        summary = {"artifacts": len(body) if isinstance(body, list) else None}
    res = {"role": req.role, "op": req.op, "run_id": run_id, "request": "%s /api/runs/%s%s" % (method, run_id, suffix),
           "status": r.status_code, "decision": s.steps[0]["decision"], "detail": _detail(r),
           "audit": [_public_entry(e, signed) for e in new], "recording": recording,
           "post_terminal": [_post_terminal_view(e) for e in late], "summary": summary,
           "response_shape": _shape(body) if r.status_code == 200 else None,
           "protected_values_in_raw_response": leaks, "bundle_exported": exported,
           "note": "The raw response stays on the server; the browser receives its status, structure and a count of protected values."}
    _journal("probe:%s:%s" % (req.role, req.op), run_id, "HTTP %d" % r.status_code, title)
    return res


def _record_counts(run_id) -> dict:
    rec = runs.Run(run_id).record
    return {"post_terminal": len(read_jsonl(store.run_dir(run_id) / "post_terminal.jsonl")),
            "post_terminal_seen": rec.get("post_terminal_events", 0), "suppressed": rec.get("denials_suppressed", 0)}


def _recording(new, late, before, after) -> dict:
    """Where the control plane recorded one request, stated exactly: in the signed chain, after the chain closed (unsigned),
    only counted (a cap was reached), or not at all. Never claims a signature that does not exist."""
    if new:
        return {"where": "audit_chain", "signed_chain": True,
                "explain": "Appended to the run's hash-chained audit log; a signed checkpoint covers it (see 'signed' per entry)."}
    if late:
        return {"where": "post_terminal", "signed_chain": False,
                "explain": "The run's signed chain is closed (terminal checkpoint written at release or failure) and is never "
                           "reopened. The control plane kept this event in post_terminal.jsonl: unsigned and informational."}
    if after["suppressed"] > before["suppressed"] or after["post_terminal_seen"] > before["post_terminal_seen"]:
        return {"where": "counted_only", "signed_chain": False,
                "explain": "A logging cap for repeated refusals was reached: the event was counted, not recorded individually."}
    return {"where": "not_recorded", "signed_chain": False,
            "explain": "The control plane wrote no audit entry for this request. It logs refused artifact reads and refused "
                       "releases; permitted reads, refused evidence reads and unknown tokens (401) are answered without one."}


def _export_if_released(run_id):
    bundle = store.p("bundles", run_id)
    if runs.Run(run_id).state == "RELEASED" and not bundle.exists():
        try:
            evidence.export_bundle(run_id, bundle)
        except (ValueError, OSError):
            return False
    return bundle.is_dir()


# ------------------------------------------------------------------------------------------------ in-memory tamper suite
@app.post("/api/lab/runs/{run_id}/tamper-suite")
def tamper_suite(run_id: str, request: Request, x_aegis_token: str | None = Header(None)):
    """The control plane's own tamper test (POST /api/runs/{id}/tamper-test) for every mode, as the reviewer, server-side.
    Each modification is applied to an in-memory copy of the stored log; the stored log is unchanged."""
    _authorize(request, x_aegis_token, "operator", "reviewer")
    _lab_run(run_id, None)
    before = hashlib.sha256((store.run_dir(run_id) / "audit.jsonl").read_bytes()).hexdigest()
    c, tok, rows = _client(), store.tokens()["reviewer"], []
    for mode in TAMPER_MODES:
        r = c.post("/api/runs/%s/tamper-test" % run_id, json={"mode": mode}, headers={"X-Aegis-Token": tok})
        if r.status_code != 200:
            rows.append({"mode": mode, "error": "HTTP %d: %s" % (r.status_code, _detail(r))})
            continue
        b = r.json()
        v = b.get("verification") or {}
        rows.append({"mode": mode, "description": b.get("description") or TAMPER_MODES[mode], "detected": b.get("detected"),
                     "verification": {"ok": v.get("ok"), "findings": [{"issue": f.get("issue")} for f in (v.get("findings") or [])][:3]}})
    after = hashlib.sha256((store.run_dir(run_id) / "audit.jsonl").read_bytes()).hexdigest()
    res = {"run_id": run_id, "rows": rows, "detected": sum(1 for x in rows if x.get("detected")), "modes": len(rows),
           "stored_log_unchanged": before == after,
           "verdict": "PASS" if all(x.get("detected") for x in rows) and before == after else "FAIL"}
    _journal("tamper-suite", run_id, res["verdict"], "in-memory tamper suite")
    return res


# ------------------------------------------------------------------------------------------------ operator session
@app.get("/session/start")
def session_start(request: Request, code: str = ""):
    """Exchange the single-use launch code (printed by scripts/start_prototype.sh) for an operator session cookie, then open
    the console. The session this browser held before, if any, is ended: one browser, one current session."""
    sid, why = lab_session.start(code[:200])
    if not sid:
        return PlainTextResponse("AegisLab console: %s.\nEach launch link works once. Print a new one with "
                                 "scripts/start_prototype.sh --link (the current code is in $AEGIS_VAR/console/launch_code).\n" % why,
                                 status_code=403)
    lab_session.end(request.cookies.get(lab_session.COOKIE))
    resp = RedirectResponse("/#/lab", status_code=303)
    resp.set_cookie(lab_session.COOKIE, sid, max_age=lab_session.SESSION_TTL_S, path="/", httponly=True, samesite="strict",
                    secure=request.url.scheme == "https")
    return resp


@app.get("/api/lab/session")
def session_info(request: Request):
    """Whether this browser holds an operator session, and its CSRF token. Readable only by pages of this origin."""
    sess = lab_session.get(request.cookies.get(lab_session.COOKIE))
    if not sess:
        return {"authenticated": False, "how": "Open the launch link printed by scripts/start_prototype.sh."}
    return {"authenticated": True, "csrf": sess["csrf"], "principal": "local operator (this console's launch link)",
            "expires_at": sess["expires_at"],
            "roles_driven": ["operator", "reviewer", "blue_participant", "red_participant"],
            "limitation": "One local operator drives every demonstration role server-side. Roles are separated inside the "
                          "control plane, but this session is not multi-user authentication."}


@app.post("/api/lab/session/end")
def session_end(request: Request):
    _authorize(request, None, "operator")
    lab_session.end(request.cookies.get(lab_session.COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(lab_session.COOKIE, path="/")
    return resp


# ------------------------------------------------------------------------------------------------ timeline
@app.get("/api/lab/timeline")
def timeline(run_id: str | None = None, limit: int = 500):
    """Merged redacted monitoring streams (the same public data as GET /api/runs/{id}/events), newest first, with the run id
    and whether a signed checkpoint already covers each entry."""
    limit = max(1, min(limit, 2000))
    ids = [r["id"] for r in runs.list_runs()]
    if run_id is not None:
        if run_id not in ids:
            raise HTTPException(404, "run not found")
        ids = [run_id]
    out = []
    for rid in ids:
        signed = _signed_upto(rid)
        for e in read_jsonl(store.run_dir(rid) / "monitor.jsonl"):
            out.append({**e, "run_id": rid, "signed": e.get("seq") is not None and e["seq"] <= signed})
    out.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return out[:limit]


# ------------------------------------------------------------------------------------------------ evidence centre
SHIPPED = {
    "DEMO-001-RELEASED": {"path": "evidence/closeout_2026-10-22/DEMO-001_released", "run_id": "DEMO-001", "expect_state": "RELEASED", "expected": "pass",
                          "label": "DEMO-001 (closeout, 22 Oct 2026)", "kind": "shipped",
                          "note": "Released run with a signed terminal checkpoint, shipped in the repository. Key read from the bundle (not pinned)."},
    "VAL-001": {"path": "evidence/validation_2026-10-22/bundles/VAL-001", "run_id": "VAL-001", "expect_state": "RELEASED", "expected": "pass",
                "label": "VAL-001 (validation, 22 Oct 2026)", "kind": "shipped", "note": "Released validation run, shipped in the repository."},
    "VAL-001-TAMPERED": {"path": "evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3", "run_id": "VAL-001", "expect_state": "RELEASED",
                         "expected": "fail", "label": "VAL-001 TAMPERED example", "kind": "shipped-tampered",
                         "note": "Deliberately tampered copy shipped as a negative example: the last 3 audit entries were removed. It must fail."},
    "DEMO-001-LEGACY": {"path": "evidence/DEMO-001", "run_id": "DEMO-001", "expect_state": "RELEASED", "expected": "fail", "label": "DEMO-001 legacy (15 Oct 2026)",
                        "kind": "shipped-legacy",
                        "note": "Submitted before terminal checkpoints existed. Strict verification rejects it by design: completeness cannot be established."},
}
BUNDLE_FILES = ("audit.jsonl", "reviewer_checkpoints.jsonl", "terminal_anchor.json", "broker_public_key.b64", "bundle.json", "manifest.json", "evidence_report.md")
TAMPER = {
    "truncate_tail": "Remove the last 3 audit entries (hide the end of the run)",
    "edit_event": "Change one recorded event: add a field to audit entry 11",
    "delete_event": "Delete one audit entry from the middle of the log",
    "reorder_events": "Swap two adjacent audit entries",
    "rehash_chain": "Rewrite an attack outcome and recompute every later hash (attacker without the signing key)",
    "forge_anchor_signature": "Flip one character of the signed terminal anchor's signature",
    "substitute_key": "Replace the public key inside the bundle with an attacker's key",
}


def _bundles() -> dict:
    out = {k: dict(v, id=k, abs=ROOT / v["path"]) for k, v in SHIPPED.items() if (ROOT / v["path"]).is_dir()}
    for rid in _lab_runs():
        d = store.p("bundles", rid)
        run = runs.Run(rid)
        if d.is_dir() and not d.is_symlink() and run.state == "RELEASED":
            out[rid] = {"id": rid, "abs": d, "path": _rel(d), "run_id": rid, "expect_state": "RELEASED", "expected": "pass", "kind": "lab",
                        "label": "%s (this console, live run)" % rid, "pin_key": runs.signer().public_b64(),
                        "pin_terminal_hash": run.record.get("terminal_checkpoint_hash"),
                        "note": "Exported by this console after the reviewer released the run. Verified with the broker key pinned and the terminal hash recorded at release."}
    return out


def _bundle(bid) -> dict:
    b = _bundles().get(bid)
    if not b:
        raise HTTPException(404, "unknown bundle")
    return b


def _links(d: Path) -> list:
    """Bundle files (or the bundle directory) that are symbolic links. The evidence centre refuses such a bundle outright:
    a link could point the verifier, a tamper copy or a download at a file outside the bundle."""
    d = Path(d)
    if d.is_symlink():
        return ["(bundle directory)"]
    return [n for n in BUNDLE_FILES if (d / n).is_symlink()]


def _public_bundle(b):
    files = [n for n in BUNDLE_FILES if (b["abs"] / n).is_file()]
    return {k: b.get(k) for k in ("id", "path", "run_id", "expect_state", "expected", "label", "kind", "note")} | {
        "files": files, "pinned": bool(b.get("pin_key")),
        "entries": sum(1 for _ in (b["abs"] / "audit.jsonl").open()) if (b["abs"] / "audit.jsonl").is_file() else None}


@app.get("/api/lab/bundles")
def bundles():
    return [_public_bundle(b) for b in _bundles().values()]


def _verify_bundle(b, path=None, quiet=False) -> dict:
    """Run the independent verifier program on a bundle directory, exactly as a reviewer would."""
    path = Path(path or b["abs"])
    links = _links(path)
    if links:
        return {"exit_code": None, "result": None, "error": "refused: symbolic link in the bundle (%s)" % ", ".join(links),
                "command": "not run"}
    cmd = [sys.executable, "-m", "aegis.verify_cli", "--bundle", str(path), "--run-id", b["run_id"], "--expect-state", b["expect_state"]]
    shown = ["python", "-m", "aegis.verify_cli", "--bundle", b["path"] if path == b["abs"] else "<disposable copy>", "--run-id", b["run_id"], "--expect-state", b["expect_state"]]
    if b.get("pin_key"):
        cmd += ["--pubkey", b["pin_key"]]
        shown += ["--pubkey", "<broker key, pinned>"]
        if b.get("pin_terminal_hash"):
            cmd += ["--expect-terminal-hash", b["pin_terminal_hash"]]
            shown += ["--expect-terminal-hash", b["pin_terminal_hash"][:19] + "…"]
    if not _verify_slots.acquire(blocking=False):
        if quiet:
            return {"exit_code": None, "result": None}
        raise HTTPException(429, "two verifications are already running; try again in a moment")
    try:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        t = time.monotonic()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=VERIFY_TIMEOUT_S, cwd=ROOT, env=env)
        took = time.monotonic() - t
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "result": None, "error": "verifier did not finish within %d s" % VERIFY_TIMEOUT_S, "command": " ".join(shown)}
    except OSError as exc:  # the interpreter or the verifier could not be started: no verdict at all
        return {"exit_code": None, "result": None, "error": "verifier could not be started (%s)" % type(exc).__name__, "command": " ".join(shown)}
    finally:
        _verify_slots.release()
    try:
        result = json.loads(p.stdout)
    except ValueError:
        result = None
    return {"exit_code": p.returncode, "result": result, "command": " ".join(shown), "seconds": round(took, 3),
            "stderr": [l[:240] for l in p.stderr.splitlines() if l.startswith(("WARNING", "NOTE"))][:4]}


@app.post("/api/lab/bundles/{bid}/verify")
def verify_bundle(bid: str):
    b = _bundle(bid)
    out = _verify_bundle(b)
    out["bundle"] = _public_bundle(b)
    ok = (out.get("result") or {}).get("ok")
    out["matches_expectation"] = out.get("exit_code") is not None and ((ok is True and out["exit_code"] == 0) if b["expected"] == "pass"
                                                                         else (ok is False and out["exit_code"] == 1))
    return out


def _digests(d: Path) -> dict:
    return {n: hashlib.sha256((d / n).read_bytes()).hexdigest() for n in BUNDLE_FILES if (d / n).is_file()}


def _mutate(d: Path, mode) -> str:
    audit = d / "audit.jsonl"
    lines = audit.read_text().splitlines()
    if mode == "truncate_tail":
        audit.write_text("\n".join(lines[:-3]) + "\n")
        return "removed audit entries %d-%d of %d" % (len(lines) - 2, len(lines), len(lines))
    if mode == "edit_event":
        e = json.loads(lines[10])
        e["data"] = dict(e.get("data") or {}, tampered=True)
        lines[10] = json.dumps(e, sort_keys=True)
        audit.write_text("\n".join(lines) + "\n")
        return "entry seq %s (%s): added data.tampered=true, hash left unchanged" % (e["seq"], e["type"])
    if mode == "delete_event":
        i = len(lines) // 2
        gone = json.loads(lines[i])
        del lines[i]
        audit.write_text("\n".join(lines) + "\n")
        return "deleted entry seq %s (%s)" % (gone["seq"], gone["type"])
    if mode == "reorder_events":
        i = len(lines) // 2
        a, b = json.loads(lines[i]), json.loads(lines[i + 1])
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
        audit.write_text("\n".join(lines) + "\n")
        return "swapped entries seq %s (%s) and %s (%s)" % (a["seq"], a["type"], b["seq"], b["type"])
    if mode == "rehash_chain":
        es = [json.loads(x) for x in lines]
        idx = next((i for i, e in enumerate(es) if e["type"] == "attack.evaluated"), len(es) // 2)
        old = es[idx]["data"].get("outcome")
        es[idx]["data"]["outcome"] = "safe_output" if old != "safe_output" else "unsafe_output"
        prev = es[idx]["prev"]
        for e in es[idx:]:
            e["prev"] = prev
            e["hash"] = entry_hash(e)
            prev = e["hash"]
        audit.write_text("\n".join(json.dumps(e, sort_keys=True) for e in es) + "\n")
        return "entry seq %d outcome %s -> %s; hashes of entries %d-%d recomputed so the chain itself is consistent" % (
            es[idx]["seq"], old, es[idx]["data"]["outcome"], es[idx]["seq"], es[-1]["seq"])
    if mode == "forge_anchor_signature":
        f = d / "terminal_anchor.json"
        a = json.loads(f.read_text())
        a["sig"] = ("A" if a["sig"][0] != "A" else "B") + a["sig"][1:]
        f.write_text(json.dumps(a, indent=2, sort_keys=True) + "\n")
        return "terminal_anchor.json: first signature character changed"
    if mode == "substitute_key":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64
        raw = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (d / "broker_public_key.b64").write_text(base64.b64encode(raw).decode() + "\n")
        return "broker_public_key.b64 replaced with a freshly generated key (the checkpoints were signed by the real broker key)"
    raise HTTPException(400, "unknown tamper mode")


class TamperReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str


@app.get("/api/lab/tamper-modes")
def tamper_modes():
    return {"disk_copy": TAMPER, "in_memory_run": TAMPER_MODES}


@app.post("/api/lab/bundles/{bid}/tamper")
def tamper_bundle(bid: str, req: TamperReq, request: Request, x_aegis_token: str | None = Header(None)):
    """Copy a genuine bundle to a disposable directory, change the copy, run the verifier on the copy and on the original, prove the
    original is byte-identical, delete the copy. The corrupted copy never leaves this function."""
    _authorize(request, x_aegis_token, "reviewer", "operator")
    if req.mode not in TAMPER:
        raise HTTPException(400, "unknown tamper mode")
    b = _bundle(bid)
    if b["expected"] != "pass":
        raise HTTPException(409, "tamper demonstrations start from a genuine bundle that verifies")
    if _links(b["abs"]):
        raise HTTPException(409, "refused: the bundle contains a symbolic link")
    before = _digests(b["abs"])
    work = Path(tempfile.mkdtemp(prefix="tamper-", dir=_mk(store.p("lab"))))
    try:
        copy = work / "copy"
        os.mkdir(copy)
        for n in before:  # regular files from the fixed list only; nothing else in the bundle directory is copied
            shutil.copyfile(b["abs"] / n, copy / n)
        try:
            change = _mutate(copy, req.mode)
        except (IndexError, KeyError, ValueError, TypeError):
            raise HTTPException(409, "this bundle is too short or malformed for tamper mode %s" % req.mode)
        tampered = _verify_bundle(b, path=copy)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    original = _verify_bundle(b)
    after = _digests(b["abs"])
    rejected = tampered.get("exit_code") == 1 and (tampered.get("result") or {}).get("ok") is False
    accepted = original.get("exit_code") == 0 and (original.get("result") or {}).get("ok") is True
    res = {"bundle": _public_bundle(b), "mode": req.mode, "description": TAMPER[req.mode], "change": change,
           "tampered_copy": tampered, "original": original, "original_unchanged": before == after,
           "original_sha256": {k: v[:16] for k, v in after.items()}, "copy_deleted": not work.exists(),
           "verdict": "PASS" if rejected and accepted and before == after else "FAIL"}
    _journal("tamper:" + req.mode, bid, res["verdict"], TAMPER[req.mode])
    _save_result("tamper", dict(res, run_id=b["run_id"], scenario="tamper", finished_at=time.time()))
    return res


@app.get("/api/lab/bundles/{bid}/download")
def download_bundle(bid: str):
    b = _bundle(bid)
    if b["expected"] != "pass":
        raise HTTPException(409, "only genuine bundles are offered for download")
    if _links(b["abs"]):
        raise HTTPException(409, "refused: the bundle contains a symbolic link")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in BUNDLE_FILES:
            f = b["abs"] / n
            if f.is_file() and not f.is_symlink():
                z.write(f, "%s/%s" % (bid, n))
        z.writestr("%s/VERIFY.txt" % bid, "Verify this bundle on your own machine (from the aegislab/ directory of the repository):\n\n"
                   "  python -m aegis.verify_cli --bundle %s --run-id %s --expect-state %s --pubkey <broker key obtained out of band>\n\n"
                   "Exit 0 and \"ok\": true mean the log is complete and unmodified relative to the signed terminal checkpoint.\n"
                   "bundle.json is a convenience index and is not trusted; the signed terminal_anchor.json is.\n" % (bid, b["run_id"], b["expect_state"]))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="aegislab_%s_bundle.zip"' % bid})


# ------------------------------------------------------------------------------------------------ experiments
def _experiments() -> dict:
    sys.path.insert(0, str(ROOT / "evaluation"))
    out = {}
    try:
        import check_claims
        rows, claims = check_claims.phase3_rows()
        p3 = check_claims.P3
        index = json.loads((p3 / "INDEX.json").read_text())
        latest = {}
        for e in index:
            latest[e["experiment"]] = e
        mb, lim = {}, []
        if "E1_canary_matrix" in latest:
            r1 = json.loads((p3 / latest["E1_canary_matrix"]["dir"] / "result.json").read_text())
            mb = {k: r1["model_backend"].get(k) for k in ("model_class", "inference_server", "bind", "temperature", "model_sha256", "server_version")}
            lim = r1.get("limitations", [])
        exps = []
        names = {"E1_canary_matrix": ("Direct-adapter canary matrix", ("e1_trials", "e1_bound", "e1_neg", "e1_pos")),
                 "E2_pipeline_canary": ("Full-pipeline canary runs", ("e2_iso", "e2_neg", "e2_pos")),
                 "E3_kv_cache_oracle": ("Prompt-cache oracle", ("e3_on", "e3_off", "e3_fresh", "e3_wall")),
                 "E4_injection_output_isolation": ("Prompt injection vs output isolation", ("e4",)),
                 "E5_failure_handling": ("Model-service failure handling", ("e5",))}
        for exp, e in sorted(latest.items()):
            title, keys = names.get(exp, (exp, ()))
            exps.append({"id": exp.split("_")[0], "experiment": exp, "title": title, "dir": "evidence/phase3_2026-10-23/llm/" + e["dir"],
                         "timestamp_utc": e["timestamp_utc"], "classification": e["classification"],
                         "claims": [claims[k] for k in keys if k in claims]})
        out["real_model"] = {"label": "PRECOMPUTED REAL-MODEL EVIDENCE", "model": mb, "experiments": exps, "limitations": lim,
                             "recompute": {"label": "LIVE RECOMPUTATION", "checks": len(rows), "passed": sum(1 for r in rows if r[3]),
                                           "failed": [r[0] for r in rows if not r[3]][:10],
                                           "what": "evaluation/check_claims.py phase3_rows(): result hashes vs INDEX, observation counts, source-file hashes, "
                                                   "every figure recomputed from observations.jsonl"},
                             "revalidation": [claims[k] for k in ("m_rc2", "m_p3") if k in claims]}
    except Exception as exc:  # noqa: BLE001 - a missing evidence tree degrades this section only
        out["real_model"] = {"available": False, "error": "real-model evidence could not be read (%s)" % type(exc).__name__}
    try:
        import check_claims
        trows, tclaims = check_claims.timing_rows(False)
        raw = [r for r in trows if " quotes " not in r[0] and "no unsourced" not in r[0]]
        agg = json.loads((check_claims.CO / "aggregate.json").read_text())
        buckets = []
        for b, v in sorted(agg["buckets"].items(), key=lambda kv: int(kv[0])):
            buckets.append({"bucket_ms": int(b), "heldout_accuracy": v["heldout_accuracy"], "permutation_p": v["permutation_p"],
                            "added_median_latency_ms": v.get("added_median_latency_for_answered_ms"), "verdict": v.get("verdict")})
        out["timing"] = {"label": "PRECOMPUTED (stub model, 3 complete executions, 22 Oct 2026)", "claims": tclaims, "buckets": buckets,
                         "source": "evidence/closeout_2026-10-22/timing/", "recompute": {"label": "LIVE RECOMPUTATION", "checks": len(raw),
                                                                                        "passed": sum(1 for r in raw if r[3])}}
    except Exception as exc:  # noqa: BLE001
        out["timing"] = {"available": False, "error": "timing evidence could not be read (%s)" % type(exc).__name__}
    try:
        v = ROOT / "evidence" / "validation_2026-10-22"
        iso = json.loads((v / "isolation_matrix.json").read_text())
        aud = json.loads((v / "audit_tamper.json").read_text())
        cats = aud["categories"]
        out["system_tests"] = {"label": "RECORDED SYSTEM TESTS (stub model, 22 Oct 2026)", "source": "evidence/validation_2026-10-22/", "rows": [
            {"claim": "unauthorized API cases denied", "value": "%d/%d" % (iso["denied_as_expected"], iso["cases_expect_deny"]), "file": "isolation_matrix.json"},
            {"claim": "unauthorized successes", "value": str(iso["unauthorized_succeeded"]), "file": "isolation_matrix.json"},
            {"claim": "secret-marker hits in public response bodies", "value": "%d in %d" % (iso["secret_marker_hits"], iso["public_get_bodies_scanned"]), "file": "isolation_matrix.json"},
            {"claim": "path-traversal cases rejected", "value": "%d/%d" % (iso["path_traversal_rejected"], iso["path_traversal_cases"]), "file": "isolation_matrix.json"},
            {"claim": "tamper categories detected in 30 of 30 runs", "value": "%d/%d" % (sum(c["detected"] == c["trials"] == 30 for c in cats.values()), len(cats)), "file": "audit_tamper.json"},
            {"claim": "CLI: genuine bundles accepted, tampered rejected", "value": "%d/%d, %d/%d" % (aud["cli_level"]["genuine_accepted"], aud["cli_level"]["bundles"],
                                                                                                aud["cli_level"]["tampered_rejected"], aud["cli_level"]["tampered_total"]), "file": "audit_tamper.json"},
        ]}
    except Exception as exc:  # noqa: BLE001
        out["system_tests"] = {"available": False, "error": "validation evidence could not be read (%s)" % type(exc).__name__}
    out["detector_limits"] = [
        {"item": "Re-encoded canaries (base64, ciphers, spelled-out digits) are not recognised by the broker's detector", "test": "tests/test_phase3_llm.py P3B02d"},
        {"item": "Timing padding lowers one threshold classifier to chance at 250 ms (n=200 per execution); it does not prove the channel is gone", "test": "evidence/closeout_2026-10-22/timing/"},
        {"item": "With cache_prompt=true a cached-token oracle reaches AUC 1.00: cross-session server state exists even when no content leaks", "test": "E3_kv_cache_oracle"},
        {"item": "GPU memory and accelerator KV-cache isolation were not tested (CPU llama.cpp only)", "test": "-"},
    ]
    return out


@app.get("/api/lab/experiments")
def experiments():
    return _cached("experiments", 3600, _experiments)


# ------------------------------------------------------------------------------------------------ replay
@app.get("/api/lab/replay")
def replay():
    """A recorded real execution of scripts/judge_demo.sh (23 Oct 2026), for machines where live containers cannot run."""
    f = ROOT / "evidence" / "phase4_2026-10-23" / "judge_demo_transcript.json"
    if not f.is_file():
        raise HTTPException(404, "no recording in this tree")
    d = json.loads(f.read_text())
    return {"label": "RECORDED EXECUTION (not live)", "source": _rel(f), "recorded_utc": d.get("recorded_utc"), "checks": d.get("checks"),
            "mode": d.get("mode"), "lines": [{"t": x.get("t"), "kind": x.get("kind"), "text": x.get("text", "")} for x in d.get("lines", [])]}


# ------------------------------------------------------------------------------------------------ pages
@app.get("/docs")
@app.get("/docs/oauth2-redirect")
@app.get("/redoc")
@app.get("/openapi.json")
def no_api_docs():
    """The mounted control plane would serve its interactive API docs here; the console does not expose them."""
    raise HTTPException(404, "not found")


@app.get("/")
def index():
    return FileResponse(CONSOLE / "index.html")


app.mount("/console", StaticFiles(directory=CONSOLE), name="console")
app.mount("/", api.app)  # the unchanged control plane: /api/..., the legacy static site and its fonts
