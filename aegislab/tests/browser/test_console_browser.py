"""Phase R2 browser end-to-end tests: a real console process, real rootless containers and a real Chromium.

The test starts `uvicorn aegis.console:app` on a free loopback port with its own state directory and launch code, then
drives the console the way a judge would: read-only first, then the launch link, a stepwise run (create, defence,
freeze, start, seal), the prohibited-access, cross-role and sandbox-containment scenarios, the reviewer release, strict verification,
disposable-copy and in-memory tamper checks, the signed audit log and the observed overlay on the isolation graph. It
repeats the main pages at a phone width. Screenshots of the real states go to docs/prototype/screenshots/r2/.

Needs Playwright with its Chromium (not part of the console's own virtualenv) plus Podman and the sandbox image:
    python -m venv /tmp/pw && /tmp/pw/bin/pip install playwright==1.64.1 pytest && /tmp/pw/bin/playwright install chromium
    /tmp/pw/bin/python -m pytest -q tests/browser
The console itself always runs from the repository's .venv.
"""
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

ROOT = Path(__file__).resolve().parents[2]
SHOTS = ROOT.parent / "docs" / "prototype" / "screenshots" / "r2"
UVICORN = ROOT / ".venv" / "bin" / "uvicorn"
IMAGE = "localhost/aegislab-sandbox:0.1"
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}


def _image_ready():
    if not shutil.which("podman"):
        return False
    try:
        return subprocess.run(["podman", "image", "exists", IMAGE], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [pytest.mark.podman,
              pytest.mark.skipif(not UVICORN.exists(), reason="the repository .venv is missing"),
              pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")]


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    var = tmp_path_factory.mktemp("console_var")
    port, code = _free_port(), secrets.token_urlsafe(24)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_MODEL") and k != "AEGIS_DEMO_MODE"}
    env.update(AEGIS_VAR=str(var), AEGIS_CONSOLE_LAUNCH_CODE=code, PYTHONDONTWRITEBYTECODE="1")
    log = open(var / "uvicorn.log", "w")
    proc = subprocess.Popen([str(UVICORN), "aegis.console:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
                            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/lab/status", timeout=30) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(0.3)
    else:
        proc.terminate()
        raise RuntimeError("console did not start: " + (var / "uvicorn.log").read_text()[-2000:])
    SHOTS.mkdir(parents=True, exist_ok=True)
    yield {"base": base, "code": code, "var": var}
    proc.terminate()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()
    left = subprocess.run(["podman", "ps", "-a", "--filter", "label=aegislab=1", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.split()
    mine = [n for n in left if n.startswith("aegis-lab-")]
    assert not mine, "containers left behind: %s" % mine


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _watch(page):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "403" not in m.text and "409" not in m.text else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    return errors


def _no_overflow(page):
    w = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
    assert w[0] <= w[1], "horizontal overflow %s" % w


def _shot(page, name):
    expect(page.locator("#toast")).not_to_have_class(re.compile(r"\bshow\b"), timeout=8_000)   # wait out a notice
    page.wait_for_timeout(400)   # let the entrance transitions finish
    page.screenshot(path=str(SHOTS / name), full_page=False)


def _go(page, base, hashpath):
    page.goto(base + "/" + hashpath)
    page.wait_for_load_state("networkidle")


def _run_box_state(page, state, timeout=180_000):
    expect(page.locator("#run-sel")).to_contain_text("LAB-001: " + state, timeout=timeout)


def test_judge_flow_desktop(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    errors = _watch(page)

    # 1. read-only without the launch link: every write control is disabled and the console says why
    _go(page, base, "#/lab")
    expect(page.locator("#sess")).to_contain_text("Read-only")
    expect(page.locator("#start-run")).to_be_disabled()
    r = page.request.post(base + "/api/lab/runs", data={"stop_after": "created"})
    assert r.status == 403 and "operator session" in r.json()["detail"]
    _shot(page, "01_lab_read_only.png")

    # 2. the launch link starts the operator session; the cookie is HttpOnly so page JavaScript never sees it
    page.goto(base + "/session/start?code=" + server["code"])
    page.wait_for_url("**/#/lab")
    expect(page.locator("#sess")).to_contain_text("Operator session")
    assert "aegis_console" not in page.evaluate("document.cookie")
    assert server["code"] not in page.content()
    cookie = [c for c in ctx.cookies() if c["name"] == "aegis_console"][0]
    assert cookie["httpOnly"] and cookie["sameSite"] == "Strict"

    # 3. stepwise run: create with the hardened profile, freeze, start, observe until sealed
    page.select_option("#bucket", "0")
    page.select_option("#prof1", "hardened")
    page.click("#start-run")
    _run_box_state(page, "CREATED", 30_000)
    expect(page.locator("#last-step")).to_contain_text("HTTP 200")
    expect(page.locator("#run-box")).to_contain_text("Hardened defence")
    _shot(page, "02_run_created.png")
    page.click("[data-step=freeze]")
    _run_box_state(page, "FROZEN", 30_000)
    page.click("[data-step=start]")
    _run_box_state(page, "SEALED")
    expect(page.locator("#run-box")).to_contain_text("signed up to #")
    _shot(page, "03_run_sealed.png")

    # 4. scenario B: unauthorised cross-role access is denied and audited
    for sid, shot in (("prohibited-access", "04_prohibited_access.png"), ("cross-role-isolation", "05_cross_role.png")):
        _go(page, base, "#/lab?open=" + sid)
        page.click("#do-scn")
        res = page.locator("#scn-result")
        expect(res.locator(".verdict")).to_contain_text("PASS", timeout=60_000)
        expect(res).to_contain_text("DENIED")
        expect(res).to_contain_text("Audit entry #")
        expect(res).to_contain_text("LIVE SYSTEM TEST")
        _shot(page, shot)

    # 4b. scenario C: a fresh container with red's hardening flags probes the network, the filesystem and its mailbox
    _go(page, base, "#/lab?open=sandbox-containment")
    page.click("#do-scn")
    res = page.locator("#scn-result")
    expect(res.locator(".verdict")).to_contain_text("PASS", timeout=120_000)
    expect(res).to_contain_text("LIVE SANDBOX")
    expect(res).to_contain_text("podman run")
    _shot(page, "05b_sandbox_containment.png")

    # 5. scenario A: the reviewer release, confirmed in the dialog, closes the run with a terminal checkpoint
    _go(page, base, "#/lab")
    page.click("[data-step=release]")
    expect(page.locator("#confirm")).to_be_visible()
    page.click("#confirm-ok")
    _run_box_state(page, "RELEASED", 60_000)
    expect(page.locator("#run-box")).to_contain_text("Outcomes")
    _shot(page, "06_run_released.png")

    # 6. scenario D: strict verification, a tampered disposable copy, and the in-memory suite
    _go(page, base, "#/evidence?open=LAB-001")
    page.click("#do-verify")
    expect(page.locator("#v-out")).to_contain_text("as expected", timeout=60_000)
    expect(page.locator("#v-out")).not_to_contain_text("NOT as expected")
    page.select_option("#t-mode", "edit_event")
    page.click("#do-tamper")
    out = page.locator("#t-out")
    expect(out.locator(".verdict")).to_contain_text("PASS", timeout=60_000)
    expect(out).to_contain_text("rejected")
    expect(out).to_contain_text("byte-identical before and after: yes")
    expect(page.locator("#t-mode")).to_have_value("edit_event")
    _shot(page, "07_evidence_tamper.png")
    page.click("#do-mem")
    expect(page.locator("#m-out .verdict")).to_contain_text("PASS", timeout=60_000)
    expect(page.locator("#m-out")).to_contain_text("12 of 12")
    expect(page.locator("#m-out")).to_contain_text("stored log unchanged: yes")

    # 7. the signed audit log of the run, filtered server-side to policy denials
    _go(page, base, "#/audit?src=log&run=LAB-001")
    expect(page.locator("#l-table")).to_contain_text("policy.denied", timeout=30_000)
    expect(page.locator("#l-meta")).to_contain_text("signed")
    body = page.locator("#l-table").inner_text()
    assert "payload_digest" not in body and "sha256:" not in body
    _shot(page, "08_signed_audit_log.png")

    # 8. the isolation graph marks the edges the scenarios exercised, separately from the static architecture
    _go(page, base, "#/connections?view=topology")
    expect(page.locator("#obs-toggle")).to_contain_text("Observed")
    assert page.locator("#gsvg .obsmark").count() >= 2
    _shot(page, "09_graph_observed.png")

    # 9. the request probe: the observer tries to release, the server sends it with the observer's token, policy refuses
    _go(page, base, "#/lab")
    page.select_option("#p-role", "observer")
    page.select_option("#p-op", "release")
    page.select_option("#p-run", "LAB-001")
    page.click("#p-send")
    expect(page.locator("#p-out")).to_contain_text("403", timeout=30_000)
    expect(page.locator("#p-out")).to_contain_text("only an authorised reviewer can release results")
    page.locator("#probe-box").scroll_into_view_if_needed()
    _shot(page, "10_request_probe.png")

    # 10. state-changing calls without CSRF, from another origin, or without the cookie are refused
    csrf = page.evaluate("fetch('/api/lab/session').then(r => r.json()).then(j => j.csrf)")
    no_csrf = page.evaluate("fetch('/api/lab/runs', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{\"stop_after\":\"created\"}'}).then(r => r.status)")
    assert no_csrf == 403
    cross = page.request.post(base + "/api/lab/runs", data={"stop_after": "created"}, headers={"X-Aegis-CSRF": csrf, "Origin": "http://evil.example"})
    assert cross.status == 403 and "cross-origin" in cross.json()["detail"]
    other = browser.new_context()
    anon = other.request.post(base + "/api/lab/runs", data={"stop_after": "created"}, headers={"X-Aegis-CSRF": csrf})
    assert anon.status == 403
    other.close()
    runs = page.request.get(base + "/api/runs").json()
    assert [x["id"] for x in runs if x["id"].startswith("LAB-")] == ["LAB-001"]

    for p in ("#/overview", "#/lab", "#/connections", "#/audit", "#/evidence", "#/experiments", "#/threat-model"):
        _go(page, base, p)
        _no_overflow(page)
    _go(page, base, "#/experiments")
    expect(page.locator("main")).to_contain_text("PRECOMPUTED")
    assert not errors, errors
    ctx.close()


def test_phone_width_pages(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=PHONE, device_scale_factor=2, is_mobile=True, has_touch=True)
    page = ctx.new_page()
    errors = _watch(page)
    page.goto(base + "/session/start?code=" + server["code"])
    page.wait_for_url("**/#/lab")
    expect(page.locator("#sess")).to_contain_text("Operator session")
    for p, shot in (("#/overview", "m01_overview.png"), ("#/lab", "m02_lab.png"), ("#/lab?open=prohibited-access", "m03_scenario.png"),
                    ("#/audit?src=log&run=LAB-001", "m04_audit_log.png"), ("#/evidence?open=LAB-001", "m05_evidence.png"),
                    ("#/connections?view=topology", "m06_graph.png")):
        _go(page, base, p)
        _no_overflow(page)
        _shot(page, shot)
    assert not errors, errors
    ctx.close()


def test_launch_link_with_a_wrong_code_starts_no_session(server, browser):
    ctx = browser.new_context()
    page = ctx.new_page()
    r = page.goto(server["base"] + "/session/start?code=" + "x" * 32)
    assert r.status == 403
    assert not [c for c in ctx.cookies() if c["name"] == "aegis_console"]
    s = json.loads(ctx.request.get(server["base"] + "/api/lab/session").text())
    assert s["authenticated"] is False
    ctx.close()
