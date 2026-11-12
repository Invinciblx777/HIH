"""Finale P3: drive the console with the REAL model live in a real browser (Playwright, Chromium), end to end.

    .venv-browser/bin/python scripts/real_model_console_check.py --shots <dir outside the repo> [--host-process] [--port 8412]
        [--keep-bundle <dir>]   copy the exported reviewer bundle of the run there (for the evidence folder)

It starts scripts/start_real_model_console.sh (model server in rootless Podman, --network none, UNIX socket, unless
--host-process), opens the launch link, and checks:
  1. /api/lab/status and the header label the backend "REAL MODEL · LIVE" with the model file, its sha256 prefix,
     "llama.cpp CPU" and "loopback";
  2. one lab run through the whole lifecycle CREATED > FROZEN > RUNNING > SEALED, answered by the real model; the run's Mode
     line carries the same label from the run's OWN frozen manifest; the audit log names the model (model.session_opened);
  3. all four live scenarios: prohibited access, cross-role isolation, sandbox containment, authorised release;
  4. strict verification of the exported bundle, then a tampered disposable copy that must be rejected.
Prints one PASS/FAIL line per check; exit 0 only if all pass. Screenshots go to --shots, never into the repository.
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHA_PREFIX = "74a4da8c9fdb"
MODEL_FILE = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("  (" + detail + ")") if detail else ""), flush=True)
    return ok


def start_console(port, mode):
    log = open(os.environ.get("RMC_LOG", "/dev/null"), "w") if os.environ.get("RMC_LOG") else subprocess.DEVNULL
    p = subprocess.Popen(["bash", str(ROOT / "scripts/start_real_model_console.sh"), "--port", str(port), "--reset"] + ([mode] if mode else []),
                         stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
    link, deadline = None, time.time() + 180
    lines = []
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            if p.poll() is not None:
                break
            continue
        lines.append(line.rstrip())
        m = re.search(r"(http://127\.0\.0\.1:\d+/session/start\?code=\S+)", line)
        if m:
            link = m.group(1)
            break
    if not link:
        p.kill()
        raise SystemExit("real-model console did not start:\n" + "\n".join(lines[-20:]))
    import urllib.request
    for _ in range(100):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=1).read()
            break
        except OSError:
            time.sleep(0.2)
    return p, link, [l for l in lines if "code=" not in l]


def stop_console(p):
    try:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(60)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        os.killpg(p.pid, signal.SIGKILL)


def run_state(page, state, timeout=300_000):
    expect(page.locator("#run-sel")).to_contain_text("LAB-001: " + state, timeout=timeout)


def go(page, base, hashpath):
    page.goto(base + "/" + hashpath)
    page.wait_for_load_state("networkidle")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", required=True)
    ap.add_argument("--port", type=int, default=8412)
    ap.add_argument("--host-process", action="store_true")
    ap.add_argument("--keep-bundle")
    a = ap.parse_args()
    shots = Path(a.shots)
    shots.mkdir(parents=True, exist_ok=True)
    proc, link, banner = start_console(a.port, "--host-process" if a.host_process else None)
    base = "http://127.0.0.1:%d" % a.port
    t0 = time.time()
    try:
        check("launcher banner names the real model and the isolation", any(MODEL_FILE in l and "sha256 " + SHA_PREFIX in l for l in banner),
              next((l.strip() for l in banner if "model server:" in l), ""))
        with sync_playwright() as pw:
            br = pw.chromium.launch()
            ctx = br.new_context(viewport={"width": 1440, "height": 900})
            page = ctx.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(link)
            page.wait_for_url("**/#/lab")
            expect(page.locator("#sess")).to_contain_text("Operator session")

            st = page.request.get(base + "/api/lab/status").json()
            m = st.get("model") or {}
            check("status: backend openai_compatible, label REAL MODEL · LIVE, reachable", m.get("backend") == "openai_compatible" and m.get("label") == "REAL MODEL · LIVE" and m.get("reachable") is True)
            check("status badge: model file, sha256 prefix, llama.cpp CPU, loopback", all(x in m.get("badge", "") for x in (MODEL_FILE, SHA_PREFIX, "llama.cpp CPU", "loopback")), m.get("badge", ""))
            check("status: live mode is LIVE SANDBOX / REAL MODEL", st.get("execution_modes", {}).get("live") == "LIVE SANDBOX / REAL MODEL")
            want_iso = "host-process" if a.host_process else "rootless-podman-network-none"
            check("status: model server isolation %s" % want_iso, m.get("server_isolation") == want_iso, m.get("reachability", ""))
            hdr = page.locator("#sys").inner_text()
            check("header shows REAL MODEL · LIVE", "REAL MODEL · LIVE" in hdr, hdr.strip()[:120])
            page.screenshot(path=str(shots / "r01_lab_real_model_status.png"), full_page=True)

            # lifecycle
            page.select_option("#bucket", "")  # the default policy: deadline release with a real model (finale P4)
            page.select_option("#prof1", "sample")
            page.click("#start-run")
            run_state(page, "CREATED", 30_000)
            page.click("[data-step=freeze]")
            run_state(page, "FROZEN", 30_000)
            page.click("[data-step=start]")
            run_state(page, "RUNNING", 60_000)
            page.screenshot(path=str(shots / "r02_run_running.png"), full_page=True)
            t_run = time.time()
            run_state(page, "SEALED", 600_000)
            run_s = round(time.time() - t_run, 1)
            box = page.locator("#run-box").inner_text()
            check("lab run LAB-001 reached SEALED with the real model", "SEALED" in box, "%.1f s RUNNING" % run_s)
            check("run Mode line: LIVE SANDBOX · REAL MODEL · LIVE + model file + sha256 prefix + llama.cpp CPU + loopback",
                  all(x in box for x in ("LIVE SANDBOX · REAL MODEL · LIVE", MODEL_FILE, SHA_PREFIX, "llama.cpp CPU", "loopback")))
            check("default policy with a real model: deadline release (finale P4), shown on the run card", "deadline release at t0 + " in box,
                  next((ln for ln in box.splitlines() if "deadline" in ln or "bucket" in ln), ""))
            v = page.request.get(base + "/api/lab/runs/LAB-001").json()
            rec = v["run"]
            check("run: every attack evaluated, complete, 0 model backend errors",
                  rec.get("evaluated") == rec.get("attack_count") and rec.get("complete") is True and (rec.get("model_backend_errors") or 0) == 0,
                  "%s of %s evaluated, complete=%s, errors=%s" % (rec.get("evaluated"), rec.get("attack_count"), rec.get("complete"), rec.get("model_backend_errors")))
            check("run view mode from its frozen manifest: LIVE SANDBOX / REAL MODEL", v.get("mode") == "LIVE SANDBOX / REAL MODEL" and (v.get("model") or {}).get("model_sha256_prefix") == SHA_PREFIX)
            page.screenshot(path=str(shots / "r03_run_sealed_real_model.png"), full_page=True)

            # scenarios
            for sid, needle in (("prohibited-access", "DENIED"), ("cross-role-isolation", "DENIED"), ("sandbox-containment", "podman run")):
                go(page, base, "#/lab?open=" + sid)
                page.click("#do-scn")
                res = page.locator("#scn-result")
                try:
                    expect(res.locator(".verdict")).to_contain_text("PASS", timeout=180_000)
                    expect(res).to_contain_text(needle)
                    ok = True
                except AssertionError:
                    ok = False
                check("scenario %s: PASS" % sid, ok, res.locator(".verdict").inner_text()[:80] if ok else res.inner_text()[:200])
                page.screenshot(path=str(shots / ("r04_%s.png" % sid)), full_page=True)
            go(page, base, "#/lab?open=authorized-release")
            page.click("#do-scn")
            expect(page.locator("#confirm")).to_be_visible()
            page.click("#confirm-ok")
            res = page.locator("#scn-result")
            try:
                expect(res.locator(".verdict")).to_contain_text("PASS", timeout=180_000)
                ok = True
            except AssertionError:
                ok = False
            check("scenario authorized-release: PASS (reviewer release, terminal checkpoint, bundle exported)", ok, res.inner_text()[:160].replace("\n", " "))
            page.screenshot(path=str(shots / "r05_authorized_release.png"), full_page=True)
            go(page, base, "#/lab")
            run_state(page, "RELEASED", 60_000)

            # the bundle and its audit log name the model
            bdir = ROOT / "var/console-real/bundles/LAB-001"
            audit = [json.loads(l) for l in (bdir / "audit.jsonl").read_text().splitlines() if l.strip()] if (bdir / "audit.jsonl").exists() else []
            so = next((e for e in audit if e.get("type") == "model.session_opened"), None)
            backend = ((so or {}).get("data") or {}).get("backend") or {}
            ident = backend.get("declared_identity") or {}
            check("audit model.session_opened names the weights (file, sha256) and the server isolation",
                  ident.get("model_file") == MODEL_FILE and (ident.get("model_sha256") or "").startswith(SHA_PREFIX) and ident.get("server_isolation") == want_iso,
                  json.dumps(ident)[:160])
            check("audit: requests stateless, cache_prompt false, no unsafe cache opt-in",
                  backend.get("stateless_requests") is True and "unsafe_shared_prompt_cache_experiment" not in backend
                  and (so or {}).get("data", {}).get("unsafe_shared_prompt_cache_experiment") is False)

            # verify and tamper
            go(page, base, "#/evidence?open=LAB-001")
            page.click("#do-verify")
            try:
                expect(page.locator("#v-out")).to_contain_text("as expected", timeout=90_000)
                expect(page.locator("#v-out")).not_to_contain_text("NOT as expected")
                ok = True
            except AssertionError:
                ok = False
            check("exported bundle: strict verification as expected", ok, page.locator("#v-out").inner_text()[:160].replace("\n", " "))
            page.select_option("#t-mode", "edit_event")
            page.click("#do-tamper")
            out = page.locator("#t-out")
            try:
                expect(out.locator(".verdict")).to_contain_text("PASS", timeout=90_000)
                expect(out).to_contain_text("rejected")
                ok = True
            except AssertionError:
                ok = False
            check("tampered disposable copy rejected, original byte-identical", ok and "byte-identical before and after: yes" in out.inner_text())
            page.screenshot(path=str(shots / "r06_evidence_verify_tamper.png"), full_page=True)
            go(page, base, "#/experiments")
            page.screenshot(path=str(shots / "r07_experiments.png"), full_page=True)
            check("no page errors", not errors, "; ".join(errors)[:200])
            br.close()
        if a.keep_bundle and (ROOT / "var/console-real/bundles/LAB-001").is_dir():
            dst = Path(a.keep_bundle)
            if dst.exists():
                raise SystemExit("refusing to overwrite " + str(dst))
            shutil.copytree(ROOT / "var/console-real/bundles/LAB-001", dst)
            print("bundle copied to", dst)
    finally:
        stop_console(proc)
    left = subprocess.run(["podman", "ps", "-a", "--filter", "label=aegislab-model-server=1", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.strip()
    check("model server container removed after Ctrl-C", not left, left)
    bad = [r for r in RESULTS if not r[1]]
    print("\n%d/%d checks PASS (wall %.0f s) — LIVE REAL MODEL console run" % (len(RESULTS) - len(bad), len(RESULTS), time.time() - t0))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
