"""Interactive prototype console (Phase R1): the web UI and a small, bounded lab API around the unchanged control plane.

Run:  scripts/start_prototype.sh
      (equivalent: AEGIS_VAR=var/console AEGIS_DEMO_MODE=1 uvicorn aegis.console:app --host 127.0.0.1 --port 8400)

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

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
import warnings
with warnings.catch_warnings():  # starlette's notice about httpx; the in-process client is only used for loopback calls
    warnings.simplefilter("ignore")
    from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from . import api, evidence, model_client, runs, runtime, store
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

app = FastAPI(title="AegisLab prototype console", version="r1", docs_url=None, redoc_url=None, openapi_url=None)

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
    into a same-origin caller of /api/demo/identities). Oversized bodies are refused before any handler runs."""
    if _host_only(request.headers.get("host", "")) not in _allowed_hosts():
        return JSONResponse({"detail": "host not allowed: the console answers on loopback names only"}, status_code=421)
    try:
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
    except ValueError:
        return JSONResponse({"detail": "invalid content-length"}, status_code=400)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


def _role(token):
    return api.role_of(token)  # the control plane's own constant-time token check


def _need(token, *roles):
    return api.need(token, *roles)


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
    shipped = _cached("shipped-verify", 3600, lambda: _verify_bundle(ref, quiet=True)) if ref else {}
    return {
        "control_plane": {"ok": True, "service": "aegislab-control-plane", "console": "r1"},
        "mode": "live" if podman.get("available") else "degraded",
        "mode_reason": None if podman.get("available") else podman.get("reason"),
        "demo_identities": os.environ.get("AEGIS_DEMO_MODE") == "1",
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


def _client() -> TestClient:
    """In-process client for the unchanged control plane: requests go through the same handlers, role checks and gates."""
    return TestClient(api.app, raise_server_exceptions=False, base_url="http://127.0.0.1")


def _require_live():
    st = _cached("podman", 20, _podman_status)
    if not st.get("available"):
        raise HTTPException(503, "live execution unavailable: %s. The evidence centre and the replay recording still work." % st.get("reason"))


@app.post("/api/lab/runs")
def prepare_run(req: PrepareReq, x_aegis_token: str | None = Header(None)):
    """Create, freeze and start a new evaluation run LAB-nnn as the operator, through the real API. Returns at once; the broker
    runs the red sandbox, defence runner and model worker in real rootless containers in the background."""
    _need(x_aegis_token, "operator")
    if req.timing_bucket_ms not in (0, 250):
        raise HTTPException(422, "timing_bucket_ms must be 0 or 250")
    _require_live()
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(409, "another lab action is in progress")
    try:
        existing = _lab_runs()
        if len(existing) >= MAX_LAB_RUNS:
            raise HTTPException(409, "lab run limit (%d) reached; restart with scripts/start_prototype.sh --reset" % MAX_LAB_RUNS)
        active = [r for r in existing if runs.Run(r).state == "RUNNING"]
        if active:
            raise HTTPException(409, "run %s is still executing; wait for it to seal" % active[0])
        run_id = "LAB-%03d" % (max((int(r[4:]) for r in existing), default=0) + 1)
        tok = {"X-Aegis-Token": x_aegis_token}
        c = _client()
        steps = []
        for method, path, body in (("POST", "/api/runs", {"run_id": run_id, "timing_bucket_ms": req.timing_bucket_ms, "tags": ["lab", "console"]}),
                                   ("POST", "/api/runs/%s/freeze" % run_id, None), ("POST", "/api/runs/%s/start" % run_id, None)):
            r = c.request(method, path, json=body, headers=tok)
            steps.append({"actor": "operator", "action": "%s %s" % (method, path), "status": r.status_code,
                          "detail": _detail(r)})
            if r.status_code != 200:
                raise HTTPException(502 if r.status_code >= 500 else r.status_code,
                                    "%s %s failed with HTTP %d: %s" % (method, path, r.status_code, _detail(r)))
        _journal("prepare", run_id, "STARTED", "operator created, froze and started %s" % run_id)
        return {"run_id": run_id, "steps": steps, "state": runs.Run(run_id).state}
    finally:
        _lab_lock.release()


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
def run_scenario(sid: str, req: ScenarioReq, x_aegis_token: str | None = Header(None)):
    if sid not in SCENARIOS:
        raise HTTPException(404, "unknown scenario")
    _need(x_aegis_token, "operator")
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
        if d.is_dir() and run.state == "RELEASED":
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
def tamper_bundle(bid: str, req: TamperReq, x_aegis_token: str | None = Header(None)):
    """Copy a genuine bundle to a disposable directory, change the copy, run the verifier on the copy and on the original, prove the
    original is byte-identical, delete the copy. The corrupted copy never leaves this function."""
    _need(x_aegis_token, "reviewer", "operator")
    if req.mode not in TAMPER:
        raise HTTPException(400, "unknown tamper mode")
    b = _bundle(bid)
    if b["expected"] != "pass":
        raise HTTPException(409, "tamper demonstrations start from a genuine bundle that verifies")
    before = _digests(b["abs"])
    work = Path(tempfile.mkdtemp(prefix="tamper-", dir=_mk(store.p("lab"))))
    try:
        copy = work / "copy"
        os.mkdir(copy)
        for n in before:  # regular files from the fixed list only; nothing else in the bundle directory is copied
            shutil.copyfile(b["abs"] / n, copy / n)
        change = _mutate(copy, req.mode)
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
    return res


@app.get("/api/lab/bundles/{bid}/download")
def download_bundle(bid: str):
    b = _bundle(bid)
    if b["expected"] != "pass":
        raise HTTPException(409, "only genuine bundles are offered for download")
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
