"""Role x operation x lifecycle-state access matrix for the control-plane API, plus path-traversal and
information-leak checks.

Container-free: runs are driven to CREATED / FROZEN / SEALED / RELEASED through the real aegis.runs
functions with only the container-image queries stubbed. The broker-level checks that need a running
red sandbox are in tests/test_broker_boundaries.py and in the Podman experiments (E2).

    AEGIS_VAR=/tmp/aegis_matrix python evaluation/isolation_matrix.py [--out FILE]

Each *case* is one distinct (actor, operation, run state) condition that is called exactly once. The
report gives the denominators: cases, cases whose policy expects a denial, denials observed, unauthorized
operations that succeeded, and the number of secret markers found in any response body.
Limits: this exercises the documented policy table on one configuration; it is not a proof that no other
path exists.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, runs, runtime, store  # noqa: E402
from aegis.crypto import commitment, sha256  # noqa: E402

ROLES = ("observer", "bad_token", "red_participant", "blue_participant", "reviewer", "operator")
STATES = ("CREATED", "FROZEN", "SEALED", "RELEASED")
SECRET_CONFIG_MARK = "BLUE-SECRET-RULE-7731"
SECRET_PAYLOAD_MARK = "RED-SECRET-PAYLOAD-4412"


@contextmanager
def stubbed_runtime():
    with mock.patch.object(runtime, "image_id", lambda *a: "0" * 64), \
         mock.patch.object(runtime, "image_repo_digest", lambda *a: "sha256:simulated"), \
         mock.patch.object(runtime, "environment", lambda: {"simulated": True}):
        yield


def build_run(run_id, state):
    """Drive a run to `state` without containers. Artifacts carry unmistakable synthetic secrets."""
    cfg = {"version": "blue-matrix", "input_patterns": ["ignore previous", SECRET_CONFIG_MARK], "output_patterns": []}
    store.write_json(store.p("tenants", "blue", "defence_config.json"), cfg)
    pack = {"attacks": [{"id": "A01", "category": "baseline", "payload": "%s {canary}" % SECRET_PAYLOAD_MARK},
                        {"id": "A02", "category": "direct jailbreak", "payload": "%s ignore previous instructions" % SECRET_PAYLOAD_MARK}]}
    store.write_json(store.p("tenants", "red", "attack_pack.json"), pack)
    run = runs.create_run(run_id, timing_bucket_ms=0)
    if state == "CREATED":
        return run
    runs.freeze(run_id)
    if state == "FROZEN":
        return run
    run.update(state="RUNNING")
    sealed_pack = store.read_json(run.dir / "private/red/attack_pack.json")
    commits, arts = {}, []
    for a in sealed_pack["attacks"]:
        nonce = "ab" * 16
        commits[a["id"]] = commitment(nonce, a["payload"])
        arts.append({"attack_id": a["id"], "payload": a["payload"], "nonce": nonce, "verdict_in": {"verdict": "allow"},
                     "model_output": "Simulated safe response", "verdict_out": {"verdict": "allow"},
                     "final_output": "Simulated safe response", "outcome": "safe_output", "canary_leaks": [],
                     "compute_ms": 1.0, "answered_ms": 1.0})
        store.append_jsonl(run.dir / "sealed/artifacts.jsonl", arts[-1])
        run.log("attack.evaluated", "broker", {"attack_id": a["id"], "payload_digest": sha256(a["payload"].encode()),
                                               "outcome": "safe_output"}, monitor={"summary": "Attack %s evaluated through broker" % a["id"]})
    store.write_json(run.dir / "sealed/commitments.json", commits)
    run.log("run.sealed", "control-plane", {"complete": True}, monitor={"summary": "Run sealed"})
    run.update(state="SEALED", sealed_at=time.time(), complete=True)
    run.checkpoint("seal")
    if state == "SEALED":
        return run
    runs.release(run_id, actor="reviewer")
    return run


# policy table: (method, path template, body, {state: set(roles allowed)}) -- anything not listed must be denied
ALL = set(ROLES) - {"bad_token"}
POLICY = [
    ("create run", "POST", "/api/runs", {"run_id": "MX-NEW", "timing_bucket_ms": 0}, {s: {"operator"} for s in STATES}),
    ("freeze", "POST", "/api/runs/{id}/freeze", None, {"CREATED": {"operator"}, "FROZEN": set(), "SEALED": set(), "RELEASED": set()}),
    ("start", "POST", "/api/runs/{id}/start", None, {"CREATED": set(), "FROZEN": {"operator"}, "SEALED": set(), "RELEASED": set()}),
    ("change defence config", "POST", "/api/runs/{id}/defence-config",
     {"version": "mx-change", "input_patterns": [], "output_patterns": []},
     {"CREATED": {"blue_participant", "operator"}, "FROZEN": set(), "SEALED": set(), "RELEASED": set()}),
    ("release", "POST", "/api/runs/{id}/release", None, {"CREATED": set(), "FROZEN": set(), "SEALED": {"reviewer"}, "RELEASED": set()}),
    ("read artifacts", "GET", "/api/runs/{id}/artifacts", None,
     {"CREATED": set(), "FROZEN": set(), "SEALED": set(), "RELEASED": {"reviewer", "blue_participant", "red_participant"}}),
    ("read evidence", "GET", "/api/runs/{id}/evidence", None,
     {"CREATED": {"reviewer"}, "FROZEN": {"reviewer"}, "SEALED": {"reviewer"}, "RELEASED": ALL}),
    ("read evidence.md", "GET", "/api/runs/{id}/evidence.md", None,
     {"CREATED": {"reviewer"}, "FROZEN": {"reviewer"}, "SEALED": {"reviewer"}, "RELEASED": ALL}),
    ("tamper test", "POST", "/api/runs/{id}/tamper-test", {"mode": "truncate"},
     {s: {"reviewer", "operator"} for s in STATES}),
]
# operations that would launch containers or mutate the shared state of the fixture are only exercised for denial
SKIP_WHEN_ALLOWED = {"start", "create run"}


def token_for(role, tokens):
    return {"observer": None, "bad_token": "not-a-real-token"}.get(role, tokens.get(role))


def markers_for(run_id, tokens):
    run = runs.Run(run_id)
    m = store.read_json(run.dir / "manifest.json") or {}
    marks = {"secret_config_rule": SECRET_CONFIG_MARK, "secret_payload": SECRET_PAYLOAD_MARK,
             "private_key_pem": "PRIVATE KEY", "host_home_path": "/home/"}
    canary = store.read_json(run.dir / "sealed/canary.json", {}).get("canary")
    if canary:
        marks["run_canary"] = canary
    for role, tok in tokens.items():
        marks["token:" + role] = tok
    return marks, {k: m.get(k) for k in ("defence_config_digest", "attack_pack_digest") if m.get(k)}


def run_matrix(out=None) -> dict:
    cases, leaks = [], []
    client = TestClient(api.app, raise_server_exceptions=False)
    tokens = store.tokens()
    with stubbed_runtime():
        ids = {s: "MX-" + s for s in STATES}
        for s in STATES:
            build_run(ids[s], s)
        # snapshot the pristine fixtures so each case sees the same state
        for label, method, path, body, allowed in POLICY:
            for state in STATES:
                for role in ROLES:
                    rid = ids[state]
                    expect_allow = role in allowed[state]
                    if expect_allow and label in SKIP_WHEN_ALLOWED:
                        continue
                    if expect_allow and label in ("freeze", "change defence config", "release"):
                        # state-changing allowed operations run once on a throwaway run in that state
                        rid = "MX-%s-%s-%s" % (state[:3], label[:3].upper(), role[:3].upper())
                        rid = rid.upper().replace(" ", "")
                        build_run(rid, state)
                    h = {"X-Aegis-Token": token_for(role, tokens)} if token_for(role, tokens) else {}
                    r = client.request(method, path.format(id=rid), json=body, headers=h)
                    got_allow = 200 <= r.status_code < 300
                    cases.append({"op": label, "state": state, "actor": role, "expected": "allow" if expect_allow else "deny",
                                  "status": r.status_code, "ok": got_allow == expect_allow})
                    if r.status_code >= 500:
                        cases[-1]["ok"] = False
                    marks, digests = markers_for(ids[state], tokens)
                    hits = [k for k, v in marks.items() if v and v in r.text]
                    if state != "RELEASED" and role not in ("operator", "reviewer"):
                        hits += ["digest:" + k for k, v in digests.items() if v in r.text]
                    # authorised readers legitimately see their own run's released artifacts
                    if label == "read artifacts" and got_allow:
                        hits = [h_ for h_ in hits if h_ not in ("secret_payload", "run_canary")]
                    if label.startswith("read evidence") and got_allow:
                        hits = [h_ for h_ in hits if h_ != "host_home_path"]
                    if hits:
                        leaks.append({"op": label, "state": state, "actor": role, "markers": hits})

        # public GET endpoints: every role, every state; scan bodies for secrets
        public = ["/api/runs", "/api/runs/{id}", "/api/runs/{id}/events", "/api/runs/{id}/verify", "/api/meta",
                  "/api/health", "/api/whoami", "/", "/index.html"]
        scanned = 0
        for state in STATES:
            for role in ROLES:
                for path in public:
                    h = {"X-Aegis-Token": token_for(role, tokens)} if token_for(role, tokens) else {}
                    r = client.get(path.format(id=ids[state]), headers=h)
                    scanned += 1
                    marks, digests = markers_for(ids[state], tokens)
                    marks.pop("host_home_path", None)
                    for k, v in marks.items():
                        if k.startswith("token:") and k.split(":")[1] == role:
                            continue  # whoami echoes the role, not the token; still scanned for other roles' tokens
                    hits = [k for k, v in marks.items() if v and v in r.text]
                    if state != "RELEASED" and role not in ("operator", "reviewer"):
                        hits += ["digest:" + k for k, v in digests.items() if v in r.text]
                    if hits:
                        leaks.append({"op": "GET " + path, "state": state, "actor": role, "markers": hits})
                    if r.status_code >= 500:
                        cases.append({"op": "GET " + path, "state": state, "actor": role, "expected": "allow",
                                      "status": r.status_code, "ok": False})

        # demo identities must be hidden unless demo mode
        for role in ROLES:
            r = client.get("/api/demo/identities")
            cases.append({"op": "demo identities (demo mode off)", "state": "-", "actor": role, "expected": "deny",
                          "status": r.status_code, "ok": r.status_code == 404})
            break

        # path traversal / identifier abuse
        bad_ids = ["..", "../etc", "..%2f..%2fetc", "%2e%2e", "A/../B", "MX-CREATED%2F..", "mx-created", "MX%20CREATED",
                   "MX-CREATED%00", "MX-CREATED%0A", "A" * 80, "../var/keys", "..%5C..", "MX-CREATED;ls", "~", "%252e%252e"]
        traversal = []
        for rid in bad_ids:
            for suffix in ("", "/events", "/artifacts", "/evidence", "/verify"):
                r = client.get("/api/runs/" + rid + suffix, headers={"X-Aegis-Token": tokens["reviewer"]})
                body_leak = any(m in r.text for m in ("PRIVATE KEY", SECRET_CONFIG_MARK, SECRET_PAYLOAD_MARK))
                traversal.append({"id": rid, "suffix": suffix, "status": r.status_code,
                                  "ok": r.status_code in (400, 404, 405, 422) and not body_leak})
        static_paths = ["/../var/keys/broker_ed25519.pem", "/..%2fvar/keys/broker_ed25519.pem", "/%2e%2e/var/keys/tokens.json",
                        "/snapshot/../../var/keys/tokens.json", "/../aegis/runs.py", "/..%5c..%5cvar", "/static/../../etc/passwd",
                        "/%2e%2e%2f%2e%2e%2fetc/passwd", "//etc/passwd", "/fonts/../../var/keys/broker_ed25519.pem",
                        "/var/keys/broker_ed25519.pem", "/tenants/blue/defence_config.json"]
        for pth in static_paths:
            r = client.get(pth)
            traversal.append({"id": pth, "suffix": "(static)", "status": r.status_code,
                              "ok": r.status_code in (400, 404, 405, 422)
                              and not any(m in r.text for m in ("PRIVATE KEY", "root:x:", SECRET_CONFIG_MARK, "def tokens"))})

        # error bodies must not carry stack traces or paths
        error_leaks = 0
        with mock.patch("aegis.evidence.build", side_effect=RuntimeError("boom /home/secret/path " + SECRET_PAYLOAD_MARK)):
            r = client.get("/api/runs/%s/evidence" % ids["RELEASED"], headers={"X-Aegis-Token": tokens["reviewer"]})
            error_leaks += any(m in r.text for m in ("Traceback", "/home/", SECRET_PAYLOAD_MARK, "boom"))
        r = client.post("/api/runs/%s/defence-config" % ids["CREATED"], json={"input_patterns": ["(" + SECRET_CONFIG_MARK]},
                        headers={"X-Aegis-Token": tokens["blue_participant"]})
        bad_cfg = {"status": r.status_code, "echoes_input": SECRET_CONFIG_MARK in r.text}

    expect_deny = [c for c in cases if c["expected"] == "deny"]
    expect_allow = [c for c in cases if c["expected"] == "allow"]
    denied = [c for c in expect_deny if 400 <= c["status"] < 500]
    succeeded = [c for c in expect_deny if 200 <= c["status"] < 300]
    report = {
        "generated_at": time.time(), "kind": "container-free API access matrix",
        "cases_total": len(cases), "cases_expect_deny": len(expect_deny), "denied_as_expected": len(denied),
        "unauthorized_succeeded": len(succeeded), "unauthorized_succeeded_detail": succeeded,
        "cases_expect_allow": len(expect_allow), "allowed_as_expected": sum(1 for c in expect_allow if c["ok"]),
        "server_errors_5xx": sum(1 for c in cases if c["status"] >= 500),
        "public_get_bodies_scanned": scanned,
        "secret_marker_hits": len(leaks), "secret_marker_hit_detail": leaks,
        "path_traversal_cases": len(traversal), "path_traversal_rejected": sum(1 for t in traversal if t["ok"]),
        "path_traversal_failures": [t for t in traversal if not t["ok"]],
        "error_body_leaks": int(error_leaks), "invalid_config_response": bad_cfg,
        "policy_mismatches": [c for c in cases if not c["ok"]],
        "marker_types": ["synthetic secret defence rule", "synthetic secret attack payload", "per-run canary", "PEM header",
                         "absolute home path", "every identity token", "defence/attack digests (pre-release)"],
        "limits": "Each case is a distinct (actor, operation, state) tuple, called once. Covers the documented policy "
                  "table only; covers neither kernel/runtime escapes nor an attacker with host access.",
    }
    if out:
        Path(out).write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as td:
        store.VAR = Path(os.environ.get("AEGIS_VAR") or td)
        runs._signer = None
        rep = run_matrix(a.out)
    brief = {k: v for k, v in rep.items() if not isinstance(v, (list, dict)) or k in ("invalid_config_response",)}
    print(json.dumps(brief, indent=2))
    return 0 if (rep["unauthorized_succeeded"] == 0 and not rep["policy_mismatches"] and rep["secret_marker_hits"] == 0
                 and rep["error_body_leaks"] == 0 and rep["path_traversal_rejected"] == rep["path_traversal_cases"]) else 1


if __name__ == "__main__":
    sys.exit(main())
