"""Deterministic, judge-facing security demonstration for AegisLab (Track 04).

    python scripts/security_demo.py [--state-dir DIR] [--pause]

Runs entirely on this machine against a FRESH state directory (default: a new temp dir; nothing under evidence/ or
var/ is read or written). The attack inputs come from samples/attack_pack.json, so every execution replays the same
inputs. Every step prints PASS or FAIL against an expected outcome; a deliberately tampered copy is never reported as
valid. Exit status 0 only if every step behaved as expected.

Steps: 1 roles & boundaries  2 legitimate run  3 denied cross-boundary operations  4 lifecycle to RELEASED
       5 signed audit verified  6 tampering on COPIES detected  7 residual-risk example  8 summary
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ap = argparse.ArgumentParser()
ap.add_argument("--state-dir")
ap.add_argument("--pause", action="store_true", help="wait for Enter between steps (live presentation)")
args = ap.parse_args()
STATE = Path(args.state_dir) if args.state_dir else Path(tempfile.mkdtemp(prefix="aegis-demo-"))
os.environ["AEGIS_VAR"] = str(STATE)
for k in [k for k in os.environ if k.startswith("AEGIS_MODEL")]:
    os.environ.pop(k)  # the demo always uses the deterministic stub

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, evidence, runtime, runs, store  # noqa: E402
from aegis.audit import read_jsonl, verify  # noqa: E402
from aegis.verify_cli import TAMPER_MODES, load_bundle, tamper_test  # noqa: E402

COL = sys.stdout.isatty()
G, R, Y, B, N = ("\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m") if COL else ("",) * 5
RESULTS = []


def step(n, title):
    if args.pause:
        input("\n[Enter] ")
    print("\n%s== %d. %s ==%s" % (B, n, title, N))


def check(label, ok, detail=""):
    RESULTS.append((label, bool(ok)))
    print("  [%s] %s%s" % ((G + "PASS" + N) if ok else (R + "FAIL" + N), label, (" - " + detail) if detail else ""))
    return ok


LIMITS = []


def limit(label, demonstrated, detail=""):
    """A documented boundary of the guarantee, shown in yellow. It is never counted as a passed security check."""
    LIMITS.append((label, bool(demonstrated)))
    print("  %s[LIMIT]%s %s%s" % (Y, N, label, (" - " + detail) if detail else ""))


def main():
    print("%sAegisLab security demonstration%s  (state dir %s, deterministic stub model, no network)" % (B, N, STATE))
    runtime.build_image(ROOT)
    # a demo that crashed earlier can leave its fixed-name containers behind, which would fail the next run
    leftover = subprocess.run(["podman", "ps", "-a", "--filter", "name=aegis-demo-s1", "--format", "{{.Names}}"],
                              capture_output=True, text=True).stdout.split()
    if leftover:
        subprocess.run(["podman", "rm", "-f", *leftover], capture_output=True)
    c = TestClient(api.app, raise_server_exceptions=False)
    tok = store.tokens()
    H = lambda role: {"X-Aegis-Token": tok[role]}  # noqa: E731

    step(1, "Roles and boundaries")
    print("  red sandbox     : reads only its own attack pack (ro), talks only to the broker mailbox, no network")
    print("  blue defence    : reads only the FROZEN defence config (ro), sees payloads only through the broker")
    print("  model worker    : fresh container per run, own mailbox only")
    print("  broker (host)   : the single path between them; identity = which mailbox the message arrived in")
    print("  reviewer/operator/observer : API roles with different rights over the same run")

    step(2, "A legitimate operation completes (run DEMO-S1: create, freeze, start)")
    run_id = "DEMO-S1"
    c.post("/api/runs", json={"run_id": run_id, "timing_bucket_ms": 0, "tags": ["security-demo"]}, headers=H("operator"))
    r = c.post("/api/runs/%s/freeze" % run_id, headers=H("operator"))
    check("operator froze the configuration", r.status_code == 200 and r.json()["state"] == "FROZEN")
    r = c.post("/api/runs/%s/defence-config" % run_id, json={"version": "late"}, headers=H("blue_participant"))
    check("blue participant cannot change the config after freeze", r.status_code == 409, "HTTP %d" % r.status_code)
    r = c.post("/api/runs/%s/start" % run_id, headers=H("operator"))
    check("operator started the run", r.status_code == 200)
    deadline = time.time() + 120
    while runs.Run(run_id).state == "RUNNING" and time.time() < deadline:
        time.sleep(0.3)
    run = runs.Run(run_id)
    check("run reached SEALED (results held behind the gate)", run.state == "SEALED", run.state)

    step(3, "Unauthorized cross-boundary operations are denied")
    pre = "/api/runs/%s/artifacts" % run_id
    cases = [("observer reads sealed artifacts", c.get(pre)),
             ("red participant reads sealed artifacts", c.get(pre, headers=H("red_participant"))),
             ("blue participant reads sealed artifacts", c.get(pre, headers=H("blue_participant"))),
             ("reviewer reads artifacts before release", c.get(pre, headers=H("reviewer"))),
             ("red participant releases the run", c.post("/api/runs/%s/release" % run_id, headers=H("red_participant"))),
             ("observer reads the evidence report", c.get("/api/runs/%s/evidence" % run_id)),
             ("forged identity token", c.get("/api/runs/%s/evidence" % run_id, headers={"X-Aegis-Token": "forged"})),
             ("path traversal in run id", c.get("/api/runs/..%2f..%2fvar/keys/broker_ed25519.pem")),
             ("signing key via the static file server", c.get("/%2e%2e/var/keys/broker_ed25519.pem"))]
    for label, r in cases:
        check("denied: " + label, 400 <= r.status_code < 500 and "PRIVATE KEY" not in r.text, "HTTP %d" % r.status_code)
    sealed = read_jsonl(run.dir / "sealed/artifacts.jsonl")
    payload = sealed[1]["payload"][:30]
    body = "".join(c.get(p, headers=h).text for p in ("/api/runs/%s/events" % run_id, "/api/runs/%s" % run_id, "/api/runs")
                   for h in ({}, H("red_participant"), H("blue_participant")))
    check("no attack payload text in anything an observer/red/blue can fetch", payload not in body)
    denied = [e for e in read_jsonl(run.dir / "audit.jsonl") if e["type"] == "policy.denied" and e["actor"] == "broker"]
    check("sandbox red agent's 5 forbidden requests were denied by the broker and logged", len(denied) == 5, "%d logged" % len(denied))
    selfcheck = store.read_json(run.dir / "sealed/red_selfcheck.json", [])
    net = [x for x in selfcheck if x["check"].startswith("tcp")]
    check("network connections from the red sandbox all failed", net and all(x["result"] == "failed" for x in net), "%d attempts" % len(net))

    step(4, "Lifecycle: reviewer verifies and releases (SEALED -> RELEASED)")
    r = c.post("/api/runs/%s/release" % run_id, headers=H("reviewer"))
    check("reviewer released the run", r.status_code == 200 and r.json()["state"] == "RELEASED", "HTTP %d" % r.status_code)
    check("participants may read artifacts only after release",
          c.get(pre, headers=H("red_participant")).status_code == 200 and c.get(pre).status_code == 403)

    step(5, "Signed audit evidence verified independently (fresh bundle, pinned key)")
    bundle = STATE / "bundles" / run_id
    info = evidence.export_bundle(run_id, bundle)
    b = load_bundle(bundle)
    v = verify(read_jsonl(b["audit"]), read_jsonl(b["checkpoints"]), b["pubkey"], expect_sealed=True, run_id=run_id,
               expected_state="RELEASED", anchor=b["anchor"])
    check("hash chain, chained checkpoints and terminal checkpoint verify", v["ok"] and v["terminal_verified"],
          "%d entries, %d checkpoints, terminal state %s" % (v["entries"], v["checkpoints_checked"], v["terminal_state"]))
    print("     verify offline: python -m aegis.verify_cli --bundle %s" % bundle)

    step(6, "Tampering on COPIES of the evidence is detected (the original is never modified)")
    audit, cps = read_jsonl(b["audit"]), read_jsonl(b["checkpoints"])
    before = (bundle / "audit.jsonl").read_bytes()
    for mode, desc in TAMPER_MODES.items():
        res = tamper_test(audit, cps, b["pubkey"], mode, anchor=b["anchor"], run_id=run_id, expected_state="RELEASED")
        first = res["verification"]["findings"][0]["issue"] if res["verification"]["findings"] else ""
        check("tamper '%s' -> verification FAILED" % mode, res["detected"], first[:80])
    check("original bundle byte-identical after all tamper tests", (bundle / "audit.jsonl").read_bytes() == before)
    bad = STATE / "tampered_copy"
    shutil.copytree(bundle, bad)
    lines = (bad / "audit.jsonl").read_text().splitlines()
    (bad / "audit.jsonl").write_text("\n".join(lines[:-3]) + "\n")
    vb = verify(read_jsonl(bad / "audit.jsonl"), read_jsonl(bad / "reviewer_checkpoints.jsonl"), b["pubkey"],
                expect_sealed=True, run_id=run_id, expected_state="RELEASED", anchor=b["anchor"])
    check("CLI-level: copy with the last 3 events removed is rejected", not vb["ok"], "; ".join(f["issue"][:70] for f in vb["findings"][:1]))
    print("  %sVerification of the tampered copy: %s%s" % (R, "FAILED (as it must)" if not vb["ok"] else "PASSED (BUG)", N))

    step(7, "Residual risk: where the guarantee stops")
    note = []
    # (a) an attacker who can also rewrite EVERY retained copy and who holds the signing key can forge a consistent history
    key_holder = runs.signer()
    forged = copy.deepcopy(audit)
    forged[12]["data"]["outcome"] = "safe_output"
    prev = forged[12]["prev"]
    from aegis.audit import GENESIS, checkpoint_hash, entry_hash
    for e in forged[12:]:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    body = {"v": 2, "run_id": run_id, "seq": len(forged), "head": forged[-1]["hash"], "event_count": len(forged), "cp_seq": 1,
            "prev_cp": GENESIS, "ts": time.time(), "reason": "terminal", "key_id": key_holder.key_id, "state": "RELEASED"}
    forged_anchor = dict(body, sig=key_holder.sign(body))
    vf = verify(forged, [forged_anchor], b["pubkey"], expect_sealed=True, run_id=run_id, expected_state="RELEASED", anchor=forged_anchor)
    limit("a forger who holds the signing key AND replaces every retained copy produces history that verifies as consistent",
          vf["ok"], "NOT a success of the control; the signing key and the reviewer's retained copy must stay out of reach of whoever can edit the run directory")
    if not vf["ok"]:
        print("  (limit not reproduced: the forged history was rejected)")
    # (b) timing: the model worker is a stub; buckets only reduce the timing signal
    vdir = ROOT / "evidence" / "validation_2026-10-22"
    timings = [json.loads((vdir / f).read_text()) for f in ("timing.json", "timing_execution_2.json") if (vdir / f).exists()]
    if timings:
        k0 = [r["conditions"]["0"] for r in timings]
        k250 = [r["conditions"]["250"] for r in timings]
        print("  timing channel (stub model, held-out, n=%d per setting, %d saved executions; chance = %.2f): no padding accuracy %s; 250 ms buckets %s"
              % (k0[0]["n_refused"] + k0[0]["n_answered"], len(timings), k0[0]["majority_baseline"],
                 "/".join("%.2f" % k["heldout_accuracy"] for k in k0), "/".join("%.2f" % k["heldout_accuracy"] for k in k250)))
        print("  reading: padding reduces the signal at a cost of ~200 ms per answered request; not shown to remove it (one weak classifier, constant-latency stub; see VALIDATION_ADDENDUM section 4).")
    print("  other documented limits: containers share the host kernel; local demo tokens, not SSO; JSON files, single host;")
    print("  the stub is not an LLM (see evidence/validation_2026-10-22/model_experiments.json for the optional real-model test).")

    step(8, "Summary")
    ok = sum(1 for _, o in RESULTS if o)
    print("  %d/%d checks behaved as expected   run id %s   state dir %s" % (ok, len(RESULTS), run_id, STATE))
    print("  %d documented limit(s) demonstrated (not counted as passes): %s" % (
        sum(1 for _, d in LIMITS if d), "; ".join(l[:60] + "..." for l, d in LIMITS if d)))
    print("  (the state dir is disposable: delete it any time)")
    bad_steps = [l for l, o in RESULTS if not o]
    for l in bad_steps:
        print("  %sFAILED%s: %s" % (R, N, l))
    return 0 if not bad_steps else 1


if __name__ == "__main__":
    sys.exit(main())
