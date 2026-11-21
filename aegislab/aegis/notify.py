"""Finale P16 (part B): incident relay to a self-hosted n8n webhook, signed, after the seal only. OFF unless AEGIS_N8N_WEBHOOK is set.

    AEGIS_N8N_WEBHOOK=http://127.0.0.1:5678/webhook/aegis-incident   loopback only (AEGIS_N8N_ALLOW_REMOTE=1 lifts that)
    AEGIS_N8N_HMAC_SECRET_FILE=/abs/path                              the shared secret, mode 0600, outside the repository

aegis/__init__.py calls install() only when AEGIS_N8N_WEBHOOK is set. install() wraps runs.Broker.execute: when execute has
returned and the run is SEALED, a daemon thread posts ONE notice. Nothing runs while red can still act (red's sandbox has been
stopped and the run sealed before the thread starts), so delivery time can never reach red's latency. The run's state, results
and audit entries up to the seal are never touched; the delivery result is appended afterwards, under the run's lifecycle lock,
as one audit entry "notify.delivery" (ok, HTTP status or error kind, duration; never the URL or the secret).

The notice carries only (build_payload): run id, state, verdict counts by outcome, the names of the anomaly detectors that
fired, a severity derived from those counts, and the digests that pin the sealed record (sealed artifacts digest, audit chain
head at the seal). It carries NO attack text, attack ids, canary, defence configuration or model output: the tests check the
exact bytes for a run with a known canary.

Signature: X-Aegis-Timestamp: <unix seconds>, X-Aegis-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>.
The receiver (tools/n8n/aegis_incident.json) recomputes it over the raw body and rejects a bad signature or a timestamp more
than 300 s old. Timeout 2 s for the whole exchange; a down or slow receiver costs the run nothing and is audited.
"""
import hashlib
import hmac
import json
import os
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import runs

TIMEOUT_S = 2.0
FORBIDDEN_KEYS = ("payload", "attack_id", "canary", "defence_config", "model_output", "final_output", "nonce", "input_patterns",
                  "output_patterns")
_orig_execute = None
_threads = []


def config(env=None):
    """(url, secret) or raises ValueError. The secret file must be a regular file with mode 0600 owned by this user."""
    env = os.environ if env is None else env
    url = (env.get("AEGIS_N8N_WEBHOOK") or "").strip()
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("AEGIS_N8N_WEBHOOK must be an http(s) URL")
    if u.hostname not in ("127.0.0.1", "localhost", "::1") and env.get("AEGIS_N8N_ALLOW_REMOTE") != "1":
        raise ValueError("AEGIS_N8N_WEBHOOK must be loopback (set AEGIS_N8N_ALLOW_REMOTE=1 to send elsewhere)")
    path = (env.get("AEGIS_N8N_HMAC_SECRET_FILE") or "").strip()
    if not path:
        raise ValueError("AEGIS_N8N_HMAC_SECRET_FILE is required")
    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.getuid():
        raise ValueError("AEGIS_N8N_HMAC_SECRET_FILE must be a regular file, mode 0600, owned by this user")
    secret = open(path, "rb").read().strip()
    if len(secret) < 32:
        raise ValueError("the HMAC secret must be at least 32 bytes")
    return url, secret


def severity(outcomes, fired, complete):
    if not complete or fired or any(outcomes.get(k) for k in ("withheld_canary", "withheld_secret", "withheld_unscanned")):
        return "high"
    if outcomes.get("unsafe_output"):
        return "medium"
    return "low"


def build_payload(run) -> dict:
    """The notice for a SEALED run, from the run record and its own audit log; counts, names and digests only."""
    rec = run.record
    sealed = summary = None
    for line in (run.dir / "audit.jsonl").read_text().splitlines():
        e = json.loads(line)
        if e["type"] == "run.sealed":
            sealed = e
        elif e["type"] == "anomaly.summary":
            summary = e["data"]
    outcomes = {str(k): int(v) for k, v in (rec.get("outcomes") or {}).items()}
    fired = sorted(k for k, v in ((summary or {}).get("detectors") or {}).items() if v.get("fired"))
    return {"event": "aegislab.run.sealed", "v": 1, "run_id": run.id, "state": run.state, "complete": bool(rec.get("complete")),
            "verdict_counts": outcomes, "evaluated": sum(outcomes.values()), "anomaly_detectors_fired": fired,
            "severity": severity(outcomes, fired, bool(rec.get("complete"))),
            "sealed_artifacts_digest": (sealed or {}).get("data", {}).get("sealed_artifacts_digest"),
            "audit_head_at_seal": (sealed or {}).get("hash"), "audit_seq_at_seal": (sealed or {}).get("seq"),
            "sealed_at": rec.get("sealed_at")}


def sign(secret: bytes, body: bytes, ts: int) -> str:
    return "v1=" + hmac.new(secret, str(ts).encode() + b"." + body, hashlib.sha256).hexdigest()


def deliver(url, secret, payload, timeout=TIMEOUT_S):
    """POST once. Returns {"ok", "status" | "error", "ms"}; never raises."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ts = int(time.time())
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "X-Aegis-Timestamp": str(ts), "X-Aegis-Signature": sign(secret, body, ts)})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(4096)
            return {"ok": 200 <= r.status < 300, "status": r.status, "ms": round((time.monotonic() - t0) * 1000, 1)}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as e:  # noqa: BLE001  (down, refused, timeout, DNS: all audited the same way)
        return {"ok": False, "error": type(e).__name__, "ms": round((time.monotonic() - t0) * 1000, 1)}


def notify_sealed(run):
    try:
        url, secret = config()
        payload = build_payload(run)
        res = deliver(url, secret, payload)
        res["payload_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        res["severity"] = payload["severity"]
    except Exception as e:  # noqa: BLE001  (bad config is audited, not raised: the run is already sealed)
        res = {"ok": False, "error": "config:" + type(e).__name__}
    with run.lifecycle():
        run.log("notify.delivery", "notifier", dict(res, receiver="n8n webhook"),
                monitor={"summary": "Incident notice %s" % ("delivered" if res.get("ok") else "NOT delivered (%s)" % (res.get("error") or res.get("status"))),
                         "decision": "info" if res.get("ok") else "warning"})
    return res


def install():
    global _orig_execute
    if _orig_execute is not None:
        return
    _orig_execute = runs.Broker.execute

    def execute(self):
        _orig_execute(self)
        if self.run.state == "SEALED":  # after the seal, red stopped: no timing channel
            t = threading.Thread(target=notify_sealed, args=(self.run,), name="notify-" + self.run.id, daemon=True)
            _threads.append(t)
            t.start()
    execute.__doc__ = _orig_execute.__doc__
    runs.Broker.execute = execute


def wait_all(timeout=10.0):
    """Tests and demos: wait for pending deliveries (each is bounded by TIMEOUT_S)."""
    end = time.monotonic() + timeout
    for t in list(_threads):
        t.join(max(0.0, end - time.monotonic()))
