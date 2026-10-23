"""Judge-facing presentation demo for AegisLab (Track 04): short, deterministic, offline.

    python scripts/judge_demo.py [--state-dir DIR] [--pause] [--record FILE.json]

PRESENTATION MODE. The original deterministic demo (scripts/security_demo.sh, 34 checks) is unchanged; this is a shorter path
for a live talk. It needs the sandbox image and the stub model only: no model download, no internet, no GPU.

  1 threat model   2 a legitimate evaluation   3 blocked unauthorized operations (API and a hostile mailbox in a real hardened container)
  4 strict verification of the completed audit bundle   5 a tampered copy is rejected   6 LLM isolation evidence (PRECOMPUTED, see step 6)
  7 residual risks

Step 6 does NOT run a model. It reads the saved Phase 3 runs under evidence/phase3_2026-10-23/llm/ (Qwen2.5-0.5B Q4_K_M, CPU llama.cpp,
loopback) and recomputes every printed figure from their raw observations.jsonl through evaluation/check_claims.py.

Everything runs against a FRESH state directory (default: a new temp dir). Nothing under evidence/ or var/ is written.
--record writes every printed line with its time offset, so a real execution can be replayed as a transcript.
Exit status 0 only if every check behaved as expected.
"""
import argparse
import json
import os
import secrets
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
ap.add_argument("--record", help="write a timestamped transcript (JSON) of everything printed")
args = ap.parse_args()
STATE = Path(args.state_dir) if args.state_dir else Path(tempfile.mkdtemp(prefix="aegis-judge-"))
os.environ["AEGIS_VAR"] = str(STATE)
for k in [k for k in os.environ if k.startswith("AEGIS_MODEL")]:
    os.environ.pop(k)  # presentation mode always uses the deterministic stub

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, evidence, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402

COL = sys.stdout.isatty()
G, R, Y, B, N = ("\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[0m") if COL else ("",) * 5
T0 = time.time()
LOG = []
RESULTS = []


def out(text="", kind="text"):
    print(text, flush=True)
    LOG.append({"t": round(time.time() - T0, 3), "kind": kind, "text": text})


def step(n, title):
    if args.pause:
        input("\n[Enter] ")
    out("")
    out("%s== %d. %s ==%s" % (B, n, title, N) if COL else "== %d. %s ==" % (n, title), "step")


def check(label, ok, detail=""):
    RESULTS.append((label, bool(ok)))
    tag = "PASS" if ok else "FAIL"
    out("  [%s] %s%s" % ((G + tag + N) if COL and ok else (R + tag + N) if COL else tag, label, (": " + detail) if detail else ""),
        "pass" if ok else "fail")
    return ok


def label_line(tag, text):
    out("  [%s] %s" % (tag, text), tag.lower().replace(" ", "_"))


def hostile_mailbox(work):
    """A real hardened red container attacks its own mailbox; then the broker's real write path runs on that mailbox."""
    base = work / "run" / "spool" / "red"
    (base / "in").mkdir(parents=True)
    (base / "out").mkdir()
    marker = "JUDGE-DEMO-VICTIM-FILE-MUST-SURVIVE\n"
    victim = work / "run" / "audit.jsonl"
    victim.write_text(marker)
    elsewhere = work / "elsewhere"
    elsewhere.mkdir()
    code = r'''
import json, os
r = {}
def attempt(name, fn):
    try:
        fn(); r[name] = "succeeded"
    except OSError as e:
        r[name] = "refused (errno %d)" % e.errno
attempt("symlink_at_guessed_temp_name", lambda: os.symlink("../../../audit.jsonl", "/aegis/spool/in/.000002.json.tmp"))
attempt("fifo_at_guessed_temp_name", lambda: os.mkfifo("/aegis/spool/in/.000003.json.tmp"))
attempt("rename_mailbox_dir", lambda: os.rename("/aegis/spool/in", "/aegis/spool/in_moved"))
attempt("remove_mailbox_dir", lambda: os.rmdir("/aegis/spool/in"))
print(json.dumps(r))
'''
    args_ = ["podman", "run", "--rm", "--name", "aegis-judge-hostile", "--label", "aegislab=1"] + runtime.hardening_flags("red")
    for h, c, m in runs.Broker._spool_mounts(base):
        args_ += ["-v", "%s:%s:Z" % (h, c)]
    args_ += [runtime.IMAGE, "python", "-c", code]
    res = subprocess.run(args_, capture_output=True, text=True)
    try:
        attempts = json.loads(res.stdout)
    except ValueError:
        return None, res.stderr.strip()[-200:]
    t = time.time()
    for name in ("000002.json", "000003.json"):
        runs._write_msg(base / "in", name, {"ok": False, "denied": True, "reason": "synthetic"})  # would block or follow on the Phase 1 code
    took = time.time() - t
    delivered = [p.name for p in (base / "in").iterdir() if p.is_file() and not p.is_symlink() and not p.name.startswith(".")]
    return {"attempts": attempts, "victim_intact": victim.read_text() == marker, "outside_files": sorted(p.name for p in elsewhere.iterdir()),
            "broker_write_seconds": took, "delivered": sorted(delivered)}, None


def main():
    out("AegisLab judge demo (PRESENTATION MODE)  state dir %s" % STATE)
    out("deterministic stub model, no network, no model download. Original demo path: scripts/security_demo.sh (unchanged).")
    runtime.build_image(ROOT)
    left = subprocess.run(["podman", "ps", "-a", "--filter", "name=aegis-judge", "--format", "{{.Names}}"],
                          capture_output=True, text=True).stdout.split()
    if left:
        subprocess.run(["podman", "rm", "-f", *left], capture_output=True)
    c = TestClient(api.app, raise_server_exceptions=False)
    tok = store.tokens()
    H = lambda role: {"X-Aegis-Token": tok[role]}  # noqa: E731

    step(1, "Threat model: who must not see what")
    out("  red team       holds attack payloads            must not read the defence rules")
    out("  blue team      holds the frozen defence config  must not see payloads before release")
    out("  model worker   answers prompts                  must not carry one session's data into another")
    out("  reviewer       receives the result              must be able to detect a changed record")
    out("  enforcement: sandboxes have no network; the broker is the only path and binds identity to the mailbox;")
    out("  roles are checked server-side; the log is hash-chained and signed; the verifier is a separate program.")
    out("  trusted, not defended: the broker and its signing key, the host kernel and container runtime.")

    step(2, "A legitimate evaluation (run JD-1, stub model)")
    run_id = "JD-1"
    c.post("/api/runs", json={"run_id": run_id, "timing_bucket_ms": 0, "tags": ["judge-demo"]}, headers=H("operator"))
    check("operator froze the configuration", c.post("/api/runs/%s/freeze" % run_id, headers=H("operator")).status_code == 200)
    check("operator started the run", c.post("/api/runs/%s/start" % run_id, headers=H("operator")).status_code == 200)
    deadline = time.time() + 120
    while runs.Run(run_id).state == "RUNNING" and time.time() < deadline:
        time.sleep(0.3)
    run = runs.Run(run_id)
    check("run reached SEALED: results held behind the gate", run.state == "SEALED", run.state)
    denied = [e for e in read_jsonl(run.dir / "audit.jsonl") if e["type"] == "policy.denied" and e["actor"] == "broker"]
    check("the red sandbox's forbidden requests were denied by the broker and logged", len(denied) == 5, "%d logged" % len(denied))

    step(3, "Blocked unauthorized operations")
    pre = "/api/runs/%s/artifacts" % run_id
    cases = [("red participant reads sealed artifacts", c.get(pre, headers=H("red_participant"))),
             ("reviewer reads artifacts before release", c.get(pre, headers=H("reviewer"))),
             ("red participant releases the run", c.post("/api/runs/%s/release" % run_id, headers=H("red_participant"))),
             ("forged identity token", c.get("/api/runs/%s/evidence" % run_id, headers={"X-Aegis-Token": "forged"}))]
    for lbl, r in cases:
        check("denied: " + lbl, 400 <= r.status_code < 500, "HTTP %d" % r.status_code)
    out("  hostile mailbox: a real rootless sandbox (no network, read-only root, no capabilities) attacks the broker's mailbox")
    work = STATE / "mailbox_attack"
    res, err = hostile_mailbox(work)
    if res is None:
        check("hostile-mailbox container ran", False, err)
    else:
        for k, v in res["attempts"].items():
            out("    inside sandbox: %-30s %s" % (k, v))
        check("broker replies were delivered as regular files despite the planted symlink and FIFO", res["delivered"] == ["000002.json", "000003.json"], str(res["delivered"]))
        check("the victim file outside the mailbox is intact (symlink not followed)", res["victim_intact"])
        check("nothing was created outside the mailbox", res["outside_files"] == [], str(res["outside_files"]))
        check("the broker did not block on the FIFO", res["broker_write_seconds"] < 2.0, "%.3f s for two writes" % res["broker_write_seconds"])
    hist = ROOT / "evidence" / "phase2_2026-10-23" / "before_fix" / "11_poc_mailbox.txt"
    if hist.exists():
        lines = hist.read_text().splitlines()
        i = next((k for k, l in enumerate(lines) if "temp-name symlink only" in l), None)
        if i is not None:
            label_line("HISTORICAL", "same attack on the Phase 1 broker (recorded 2026-10-23, evidence/phase2_2026-10-23/before_fix/11_poc_mailbox.txt):")
            for l in lines[i:i + 4]:
                out("    " + l)
            out("    reading: on the Phase 1 broker the planted symlink was followed and the victim file was overwritten (intact: False)")
    out("  regression tests: P2B01 P2B02 P2B03 P2B05 P2B06 P2B32 (tests/test_phase2_broker.py), P2C01 P2C02 (tests/test_phase2_container.py)")

    step(4, "A completed audit bundle is verified strictly")
    r = c.post("/api/runs/%s/release" % run_id, headers=H("reviewer"))
    check("reviewer released the run (SEALED -> RELEASED)", r.status_code == 200 and r.json()["state"] == "RELEASED", "HTTP %d" % r.status_code)
    bundle = STATE / "bundles" / run_id
    evidence.export_bundle(run_id, bundle)
    pinned_key = runs.signer().public_b64()  # the reviewer's own copy of the broker's public key, not the one inside the bundle
    pinned_hash = r.json().get("terminal_hash")  # the terminal hash the reviewer noted when the run was released

    def verify_cli(path):
        cmd = [sys.executable, "-m", "aegis.verify_cli", "--bundle", str(path), "--run-id", run_id, "--expect-state", "RELEASED",
               "--pubkey", pinned_key, "--expect-terminal-hash", pinned_hash]
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"ok": False, "findings": [{"issue": (p.stdout + p.stderr).strip()[-160:]}]}

    def show(v):
        for k in ("ok", "entries", "checkpoints_checked", "terminal_verified", "terminal_state", "key_source"):
            if k in v:
                out("    %-20s %s" % (k, str(v[k])[:70]))
        for f in v.get("findings", [])[:3]:
            out("    finding: " + f["issue"][:90])
    out("  $ python -m aegis.verify_cli --bundle <bundle> --run-id %s --expect-state RELEASED --pubkey <pinned> --expect-terminal-hash <noted at release>" % run_id)
    rc, v = verify_cli(bundle)
    show(v)
    check("strict verification of the complete bundle (key and terminal hash pinned)", rc == 0 and v.get("ok"), "exit %d" % rc)

    step(5, "A tampered copy is rejected")
    bad = STATE / "tampered_copy"
    shutil.copytree(bundle, bad)
    lines = (bad / "audit.jsonl").read_text().splitlines()
    (bad / "audit.jsonl").write_text("\n".join(lines[:-3]) + "\n")
    out("  the last 3 audit entries were removed from a COPY; the original bundle is not touched")
    out("  $ python -m aegis.verify_cli --bundle <tampered copy> ... (same options)")
    rc, v = verify_cli(bad)
    show(v)
    check("verification of the tampered copy FAILED, as it must", rc == 1 and not v.get("ok"), "exit %d" % rc)
    check("the original bundle still verifies", verify_cli(bundle)[0] == 0)

    step(6, "LLM isolation evidence: PRECOMPUTED from saved real-model runs (this demo does not run a model)")
    sys.path.insert(0, str(ROOT / "evaluation"))
    import check_claims
    base = ROOT / "evidence" / "phase3_2026-10-23" / "llm"
    if not (base / "INDEX.json").exists():
        label_line("NOT RUN", "evidence/phase3_2026-10-23/llm/INDEX.json is missing in this tree")
    else:
        rows, claims = check_claims.phase3_rows()
        index = {e["experiment"]: e for e in json.loads((base / "INDEX.json").read_text())}
        mb = json.loads((base / index["E1_canary_matrix"]["dir"] / "result.json").read_text())["model_backend"]
        label_line("PRECOMPUTED", "model %s, %s, %s, CPU only" % (mb["model_class"], mb["inference_server"], mb["bind"]))
        out("  the stub model ran steps 2 to 5. The figures below are from the saved runs, recomputed now from raw observations.")
        shown = (("E1_canary_matrix", ("e1_trials", "e1_bound", "e1_neg", "e1_pos")), ("E2_pipeline_canary", ("e2_iso", "e2_neg", "e2_pos")),
                 ("E3_kv_cache_oracle", ("e3_on", "e3_off", "e3_fresh")), ("E4_injection_output_isolation", ("e4",)))
        for exp, keys in shown:
            out("  %s  run %s" % (exp.split("_")[0], index[exp]["dir"]))
            for k in keys:
                for part in claims[k].split("; "):
                    out("      " + part)
            out("      raw: evidence/phase3_2026-10-23/llm/%s/observations.jsonl" % index[exp]["dir"])
        check("saved LLM runs agree with their raw observations, hashes and source files", all(r[3] for r in rows), "%d checks" % len(rows))
        out("  scope: one 0.5B model, ten probe wordings, CPU llama.cpp on loopback. GPU memory, accelerator KV cache and hardware side")
        out("  channels were NOT tested. Zero observed leaks in a finite experiment do not prove zero risk.")

    step(7, "Residual risks (stated, not hidden)")
    out("  - a compromised broker or signing key can sign a false but consistent record; only a reviewer's independent")
    out("    terminal-hash note (--expect-terminal-hash) catches a key thief who replaces every retained copy")
    out("  - the host kernel and container runtime are shared and trusted; hardware side channels are untested")
    out("  - the canary detector does not recognise every re-encoding (for example base64)")
    out("  - prompt-injection results show information-flow control, not model robustness")
    out("  - timing padding lowers one classifier's accuracy; it does not show the timing channel is gone")

    step(8, "Summary")
    ok_n = sum(1 for _, o in RESULTS if o)
    out("  %d/%d checks behaved as expected   (%.1f s)   state dir %s (disposable)" % (ok_n, len(RESULTS), time.time() - T0, STATE))
    bad_checks = [l for l, o in RESULTS if not o]
    for l in bad_checks:
        out("  FAILED: " + l)
    if args.record:
        Path(args.record).write_text(json.dumps({"mode": "judge_demo presentation mode", "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                 "checks": "%d/%d" % (ok_n, len(RESULTS)), "lines": LOG}, indent=1))
    return 0 if not bad_checks else 1


if __name__ == "__main__":
    sys.exit(main())
