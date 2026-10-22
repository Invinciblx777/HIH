"""Phase 2 extension of the access matrix: six lifecycle states (adds RUNNING and FAILED), unknown run identifiers,
identity mix-ups, and the enforcement checked at the component level as well as through the API.

Container-free (runs are driven through the real aegis.runs functions, only the image queries are stubbed).

    AEGIS_VAR=/tmp/p2matrix python evaluation/phase2_matrix.py [--out FILE]

Reported per category: attempted, denied, unexpectedly permitted, test errors (5xx or an exception in the harness).
This exercises the documented policy table on one configuration. It does not prove that no other path exists.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from fastapi.testclient import TestClient  # noqa: E402

import isolation_matrix as mx  # noqa: E402
from aegis import api, runs, store  # noqa: E402

ROLES = mx.ROLES
STATES = ("CREATED", "FROZEN", "RUNNING", "SEALED", "RELEASED", "FAILED")
ALL = set(ROLES) - {"bad_token"}
OPS = [  # label, method, path, body, {state: roles allowed}; every other (role, state) must be denied
    ("freeze", "POST", "/api/runs/{id}/freeze", None, {"CREATED": {"operator"}}),
    ("start", "POST", "/api/runs/{id}/start", None, {"FROZEN": {"operator"}}),
    ("change defence config", "POST", "/api/runs/{id}/defence-config",
     {"version": "p2", "input_patterns": [], "output_patterns": []}, {"CREATED": {"blue_participant", "operator"}}),
    ("release", "POST", "/api/runs/{id}/release", None, {"SEALED": {"reviewer"}}),
    ("read artifacts", "GET", "/api/runs/{id}/artifacts", None, {"RELEASED": {"reviewer", "blue_participant", "red_participant"}}),
    ("read evidence", "GET", "/api/runs/{id}/evidence", None,
     {s: {"reviewer"} for s in STATES} | {"RELEASED": ALL}),
    ("read evidence.md", "GET", "/api/runs/{id}/evidence.md", None,
     {s: {"reviewer"} for s in STATES} | {"RELEASED": ALL}),
    ("tamper test", "POST", "/api/runs/{id}/tamper-test", {"mode": "truncate"}, {s: {"reviewer", "operator"} for s in STATES}),
]
MUTATING = {"freeze", "change defence config", "release"}
NOT_RUN_WHEN_ALLOWED = {"start"}  # would launch containers; denial is still exercised
UNKNOWN_IDS = ["ZZ-NOPE", "MX-UNKNOWN-1", "A0"]
SECRET_MARKS = (mx.SECRET_CONFIG_MARK, mx.SECRET_PAYLOAD_MARK, "PRIVATE KEY")


def build(run_id, state):
    if state in ("CREATED", "FROZEN", "SEALED", "RELEASED"):
        return mx.build_run(run_id, state)
    run = mx.build_run(run_id, "FROZEN")
    run.update(state="RUNNING")
    if state == "RUNNING":
        return run
    run.log("run.failed", "control-plane", {"error": "SyntheticFailure", "detail": "phase2 matrix"}, checkpoint=False, close=True)
    run.update(state="FAILED")
    run.terminal_checkpoint("FAILED")
    return run


def run_extended_matrix(out=None) -> dict:
    cats = {}

    def tally(cat, expect_allow, status, leaked=False):
        c = cats.setdefault(cat, {"attempted": 0, "expected_deny": 0, "denied": 0, "unexpectedly_permitted": 0,
                                  "expected_allow": 0, "allowed": 0, "wrongly_denied": 0, "test_errors": 0, "secret_hits": 0})
        c["attempted"] += 1
        if status >= 500:
            c["test_errors"] += 1
        if expect_allow:
            c["expected_allow"] += 1
            c["allowed"] += 200 <= status < 300
            c["wrongly_denied"] += not (200 <= status < 300) and status < 500
        else:
            c["expected_deny"] += 1
            c["denied"] += 400 <= status < 500
            c["unexpectedly_permitted"] += 200 <= status < 300
        c["secret_hits"] += bool(leaked)

    client = TestClient(api.app, raise_server_exceptions=False)
    tokens = store.tokens()
    mismatches, not_sendable = [], []
    with mx.stubbed_runtime():
        ids = {s: "P2-" + s for s in STATES}
        for s in STATES:
            build(ids[s], s)
        for label, method, path, body, allowed in OPS:
            for state in STATES:
                for role in ROLES:
                    expect_allow = role in allowed.get(state, set())
                    if expect_allow and label in NOT_RUN_WHEN_ALLOWED:
                        continue
                    rid = ids[state]
                    if expect_allow and label in MUTATING:
                        rid = ("P2-%s-%s-%s" % (state[:4], label[:4], role[:3])).upper().replace(" ", "")
                        build(rid, state)
                    tok = mx.token_for(role, tokens)
                    r = client.request(method, path.format(id=rid), json=body, headers={"X-Aegis-Token": tok} if tok else {})
                    hit = any(m in r.text for m in SECRET_MARKS + tuple(v for v in tokens.values())) if not expect_allow else False
                    tally("role x operation x state: " + label, expect_allow, r.status_code, hit)
                    if (200 <= r.status_code < 300) != expect_allow or r.status_code >= 500:
                        mismatches.append({"op": label, "state": state, "role": role, "status": r.status_code})
        # unknown / foreign run identifiers: nothing may succeed or fail with a server error
        for rid in UNKNOWN_IDS:
            for label, method, path, body, _ in OPS:
                for role in ROLES:
                    tok = mx.token_for(role, tokens)
                    r = client.request(method, path.format(id=rid), json=body, headers={"X-Aegis-Token": tok} if tok else {})
                    tally("unknown run id", False, r.status_code, any(m in r.text for m in SECRET_MARKS))
                    if 200 <= r.status_code < 300 or r.status_code >= 500:
                        mismatches.append({"op": label, "state": "UNKNOWN", "role": role, "status": r.status_code})
        # public read endpoints: every role, every state, scanned for markers and tokens
        for state in STATES:
            for role in ROLES:
                for path in ("/api/runs/{id}", "/api/runs/{id}/events", "/api/runs/{id}/verify"):
                    tok = mx.token_for(role, tokens)
                    r = client.get(path.format(id=ids[state]), headers={"X-Aegis-Token": tok} if tok else {})
                    leaked = any(m in r.text for m in SECRET_MARKS + tuple(tokens.values()))
                    if role not in ("operator", "reviewer") and state != "RELEASED":
                        m = store.read_json(store.run_dir(ids[state]) / "manifest.json") or {}
                        leaked |= any(m.get(k) and m[k] in r.text for k in ("defence_config_digest", "attack_pack_digest"))
                    # an unrecognised token is rejected (401) wherever the handler resolves the caller's role
                    tally("public read endpoints", not (role == "bad_token" and path == "/api/runs/{id}"), r.status_code, leaked)
        # identity mix-ups: two tokens, token in the query string, token in other headers, odd token values
        odd = {"empty": "", "whitespace": " ", "operator_with_suffix": tokens["operator"] + "x",
               "operator_prefix": tokens["operator"][:-1], "long": "A" * 10000, "unicode": "é中",
               "nul": "a\x00b", "other_case": tokens["operator"].swapcase()}
        for label, tok in odd.items():
            try:
                r = client.post("/api/runs/%s/freeze" % ids["CREATED"], headers={"X-Aegis-Token": tok})
            except Exception:  # the HTTP client refuses to send this header value at all: not a server result
                not_sendable.append(label)
                continue
            tally("identity mix-up", False, r.status_code)
        r = client.post("/api/runs/%s/freeze?token=%s" % (ids["CREATED"], tokens["operator"]))
        tally("identity mix-up", False, r.status_code)
        r = client.post("/api/runs/%s/freeze" % ids["CREATED"], headers={"Authorization": "Bearer " + tokens["operator"],
                                                                         "X-Aegis-Role": "operator", "X-Aegis-Token": tokens["red_participant"]})
        tally("identity mix-up", False, r.status_code)
        r = client.post("/api/runs", json={"run_id": "P2-MIX", "timing_bucket_ms": 0}, headers={"X-Aegis-Token": tokens["blue_participant"]})
        tally("identity mix-up", False, r.status_code)
        # component level: the same forbidden transitions called directly, bypassing the API
        for state, fn, label in (("FROZEN", lambda r_: runs.freeze(r_), "freeze twice"),
                                 ("RUNNING", lambda r_: runs.freeze(r_), "freeze while running"),
                                 ("RUNNING", lambda r_: runs.start(r_), "start while running"),
                                 ("SEALED", lambda r_: runs.start(r_), "start sealed"),
                                 ("FAILED", lambda r_: runs.release(r_), "release failed run"),
                                 ("RUNNING", lambda r_: runs.release(r_), "release running"),
                                 ("RELEASED", lambda r_: runs.release(r_), "release twice"),
                                 ("FROZEN", lambda r_: runs.update_defence_config(r_, {"version": "x"}), "config change frozen"),
                                 ("RUNNING", lambda r_: runs.artifacts(r_), "artifacts running"),
                                 ("SEALED", lambda r_: runs.artifacts(r_), "artifacts sealed"),
                                 ("FAILED", lambda r_: runs.artifacts(r_), "artifacts failed")):
            before = (store.read_json(store.run_dir(ids[state]) / "run.json") or {}).get("state")
            try:
                fn(ids[state])
                status = 200
            except runs.GateError:
                status = 409
            except Exception:
                status = 599
            after = (store.read_json(store.run_dir(ids[state]) / "run.json") or {}).get("state")
            tally("component level (runs.* called directly)", False, status)
            if before != after:
                mismatches.append({"op": label, "state": state, "role": "component", "status": "state changed %s -> %s" % (before, after)})
    report = {"generated_at": time.time(), "kind": "Phase 2 extended access matrix (container-free)",
              "states": list(STATES), "roles": list(ROLES), "categories": cats,
              "totals": {k: sum(c[k] for c in cats.values()) for k in
                         ("attempted", "expected_deny", "denied", "unexpectedly_permitted", "expected_allow", "allowed",
                          "wrongly_denied", "test_errors", "secret_hits")},
              "mismatches": mismatches, "token_values_the_client_could_not_send": not_sendable,
              "not_tested": ["operations that launch containers when permitted (start, create)", "run-scoped identities (tokens are global per role)",
                             "WebSocket or other transports (none exist)", "any path not in the documented policy table"]}
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
        rep = run_extended_matrix(a.out)
    print(json.dumps(rep["totals"], indent=2))
    t = rep["totals"]
    return 0 if (t["unexpectedly_permitted"] == 0 and t["wrongly_denied"] == 0 and t["test_errors"] == 0 and t["secret_hits"] == 0 and not rep["mismatches"]) else 1


if __name__ == "__main__":
    sys.exit(main())
