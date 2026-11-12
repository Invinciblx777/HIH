"""Finale P5: fresh screenshots of the FINAL console UI, driven with Playwright (Chromium) from aegislab/.venv-browser.

    .venv-browser/bin/python ../finale_package/src/capture_screens.py --out <dir outside the repo> [--port 8414] [--public-port 8415]

1. Starts scripts/start_real_model_console.sh (the real model in rootless Podman, --network none) through the helpers of
   scripts/real_model_console_check.py, opens its one-time launch link (never printed, never on screen: the browser follows
   it and lands on #/lab), and drives one lab run with the default policy (real model: deadline release) to SEALED, the
   prohibited-access scenario, the reviewer's authorised release, verify and tamper on the Evidence page.
2. Takes every page at desktop 1440x900 and phone 390x844 (the phone context gets the same session cookie):
   Overview, Lab (run card "REAL MODEL · LIVE", "deadline release at t0 + 1400 ms"), Connections, Audit (signed log with the
   anomaly-detector panel open), Evidence (verify accepted; tampered copy rejected), Experiments, Threat Model.
3. Starts the read-only public demo locally (AEGIS_PUBLIC_DEMO=1 uvicorn app:app, scratch state, degraded mode) and takes
   Overview and Evidence (verify) at both sizes.
Writes PNGs plus shots.json (name, url hash, viewport, what it shows). Nothing is written into the repository.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
AEG = HERE.parent.parent / "aegislab"
sys.path.insert(0, str(AEG / "scripts"))
from real_model_console_check import go, run_state, start_console, stop_console  # noqa: E402
from playwright.sync_api import expect, sync_playwright  # noqa: E402

DESK = {"viewport": {"width": 1440, "height": 900}, "device_scale_factor": 1}
PHONE = {"viewport": {"width": 390, "height": 844}, "device_scale_factor": 2, "is_mobile": True, "has_touch": True}
LOG = []


def shot(page, out, name, what, full=False):
    page.wait_for_timeout(700)
    p = out / (name + ".png")
    page.screenshot(path=str(p), full_page=full)
    LOG.append({"file": p.name, "url_hash": page.url.split("#", 1)[-1] if "#" in page.url else "", "viewport": page.viewport_size, "full_page": full, "shows": what})
    print("shot", p.name, flush=True)


def pages(page, base, out, sfx):
    go(page, base, "#/overview")
    shot(page, out, "01_overview_" + sfx, "Overview")
    go(page, base, "#/lab")
    run_state(page, "RELEASED", 60_000)
    shot(page, out, "02_lab_" + sfx, "Lab: run card LAB-001, REAL MODEL · LIVE, deadline release")
    if sfx == "desktop":
        page.locator("#run-box").screenshot(path=str(out / "02b_run_card_desktop.png"))
        LOG.append({"file": "02b_run_card_desktop.png", "url_hash": "/lab", "viewport": page.viewport_size, "full_page": False, "shows": "the run card element only"})
    shot(page, out, "02_lab_full_" + sfx, "Lab, full page", full=True)
    go(page, base, "#/connections")
    shot(page, out, "03_connections_" + sfx, "Connections (architecture graph)")
    go(page, base, "#/audit?src=log&run=LAB-001")
    page.wait_for_selector("#anom", timeout=30_000)
    page.evaluate("document.querySelector('#anom').open = true")
    page.locator("#anom").scroll_into_view_if_needed()
    shot(page, out, "04_audit_anomaly_" + sfx, "Audit: signed log of LAB-001 with the anomaly-detector panel open")
    shot(page, out, "04_audit_full_" + sfx, "Audit, full page", full=True)
    go(page, base, "#/evidence?open=LAB-001")
    page.click("#do-verify")
    expect(page.locator("#v-out")).to_contain_text("as expected", timeout=90_000)
    page.locator("#v-out").scroll_into_view_if_needed()
    shot(page, out, "05_evidence_verify_" + sfx, "Evidence: strict verification of LAB-001 accepted")
    page.select_option("#t-mode", "edit_event")
    page.click("#do-tamper")
    expect(page.locator("#t-out")).to_contain_text("rejected", timeout=90_000)
    page.locator("#t-out").scroll_into_view_if_needed()
    shot(page, out, "06_evidence_tamper_" + sfx, "Evidence: tampered copy rejected, original byte-identical")
    go(page, base, "#/experiments")
    shot(page, out, "07_experiments_" + sfx, "Experiments")
    shot(page, out, "07_experiments_full_" + sfx, "Experiments, full page", full=True)
    go(page, base, "#/threat-model")
    shot(page, out, "08_threat_model_" + sfx, "Threat Model")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, default=8414)
    ap.add_argument("--public-port", type=int, default=8415)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base = "http://127.0.0.1:%d" % a.port
    proc, link, _ = start_console(a.port, None)
    try:
        with sync_playwright() as pw:
            br = pw.chromium.launch()
            ctx = br.new_context(**DESK)
            page = ctx.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(link)
            page.wait_for_url("**/#/lab")
            page.wait_for_load_state("networkidle")
            shot(page, out, "00_lab_before_run_desktop", "Lab before the run: header REAL MODEL · LIVE")
            page.select_option("#bucket", "")
            page.select_option("#prof1", "sample")
            page.click("#start-run")
            run_state(page, "CREATED", 30_000)
            page.click("[data-step=freeze]")
            run_state(page, "FROZEN", 30_000)
            page.click("[data-step=start]")
            run_state(page, "RUNNING", 60_000)
            shot(page, out, "02a_lab_running_desktop", "Lab: LAB-001 RUNNING with the real model")
            run_state(page, "SEALED", 600_000)
            page.locator("#run-box").scroll_into_view_if_needed()
            shot(page, out, "02a_lab_sealed_desktop", "Lab: LAB-001 SEALED, run card")
            go(page, base, "#/lab?open=prohibited-access")
            page.click("#do-scn")
            expect(page.locator("#scn-result .verdict")).to_contain_text("PASS", timeout=180_000)
            page.locator("#scn-result").scroll_into_view_if_needed()
            shot(page, out, "02c_scenario_prohibited_desktop", "Lab: prohibited-access scenario PASS")
            go(page, base, "#/lab?open=authorized-release")
            page.click("#do-scn")
            expect(page.locator("#confirm")).to_be_visible()
            page.click("#confirm-ok")
            expect(page.locator("#scn-result .verdict")).to_contain_text("PASS", timeout=180_000)
            page.locator("#scn-result").scroll_into_view_if_needed()
            shot(page, out, "02d_scenario_release_desktop", "Lab: authorised release PASS")
            pages(page, base, out, "desktop")
            pctx = br.new_context(**PHONE)
            pctx.add_cookies(ctx.cookies())
            pp = pctx.new_page()
            pp.on("pageerror", lambda e: errors.append(str(e)))
            pages(pp, base, out, "phone")
            print("page errors:", errors)
            br.close()
    finally:
        stop_console(proc)
    # the read-only public demo, locally, degraded mode
    tmp = tempfile.mkdtemp(prefix="aegis-public-")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env.update(AEGIS_VAR=tmp + "/var", AEGIS_PUBLIC_DEMO="1", PYTHONWARNINGS="ignore")
    srv = subprocess.Popen([str(AEG / ".venv/bin/uvicorn"), "app:app", "--host", "127.0.0.1", "--port", str(a.public_port), "--log-level", "warning"],
                           cwd=str(AEG), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pbase = "http://127.0.0.1:%d" % a.public_port
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(pbase + "/api/health", timeout=1).read()
                break
            except OSError:
                time.sleep(0.2)
        st = json.loads(urllib.request.urlopen(pbase + "/api/lab/status").read())
        print("public status: public_demo=%s mode=%s" % (st.get("public_demo"), st.get("mode")))
        with sync_playwright() as pw:
            br = pw.chromium.launch()
            for opts, sfx in ((DESK, "desktop"), (PHONE, "phone")):
                ctx = br.new_context(**opts)
                page = ctx.new_page()
                go(page, pbase, "#/overview")
                expect(page.locator("header")).to_contain_text("Public demo", timeout=30_000)
                shot(page, out, "09_public_overview_" + sfx, "Public read-only demo (local, AEGIS_PUBLIC_DEMO=1): degraded mode")
                go(page, pbase, "#/evidence?open=DEMO-001-RELEASED")
                page.click("#do-verify")
                expect(page.locator("#v-out")).to_contain_text("as expected", timeout=90_000)
                page.locator("#v-out").scroll_into_view_if_needed()
                shot(page, out, "10_public_verify_" + sfx, "Public read-only demo: bundle verify accepted")
                ctx.close()
            br.close()
    finally:
        srv.terminate()
        srv.wait(20)
    (out / "shots.json").write_text(json.dumps({"captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "shots": LOG}, indent=1))
    print("%d shots" % len(LOG))


if __name__ == "__main__":
    main()
