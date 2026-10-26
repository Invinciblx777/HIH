"""Phase R3 container-free browser tests: a real console process (degraded mode, forced by a stand-in `podman` that always
fails), a real Chromium, and the real verifier. Runs on any machine with Python and Playwright, including hosted CI.

Covers: read-only mode, a wrong launch code, the operator login, single use of the launch link, refresh, logout, the
independent verifier on an authentic and on a tampered bundle, a tamper demonstration on a disposable copy, oversized and
malformed requests from the page, an unreachable backend, honest labels when live containers are unavailable, and the
main pages at desktop and phone widths. Screenshots go to docs/prototype/screenshots/r3/.
"""
import json

import pytest

from conftest import (DESKTOP, PHONE, console_python_missing, csrf_of, go, issue_code, no_overflow, playwright_api, random_code,
                      require, running_console, shot, watch, SKIP_DEP)

sync_api = playwright_api()
expect = sync_api.expect
require(console_python_missing(), prefix=SKIP_DEP, env="AEGIS_REQUIRE_BROWSER")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    var = tmp_path_factory.mktemp("console_core_var")
    shim = tmp_path_factory.mktemp("no_podman")
    (shim / "podman").write_text("#!/bin/sh\necho 'stand-in: live containers disabled for the container-free browser tests' >&2\nexit 125\n")
    (shim / "podman").chmod(0o755)
    import os
    with running_console(var, {"PATH": "%s:%s" % (shim, os.environ.get("PATH", ""))}) as s:
        yield s


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def _login(page, server, code=None):
    page.goto(server["base"] + "/session/start?code=" + (code or issue_code(server["var"])))
    page.wait_for_url("**/#/lab")
    expect(page.locator("#sess")).to_contain_text("Operator session")


def test_read_only_wrong_code_login_single_use_and_refresh(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    errors = watch(page)

    # read-only without the launch link; live mode is honestly unavailable on this console
    go(page, base, "#/lab")
    expect(page.locator("#sess")).to_contain_text("Read-only")
    expect(page.locator("#sess-end")).to_be_hidden()
    expect(page.locator("#start-run")).to_be_disabled()
    expect(page.locator("main")).to_contain_text("UNAVAILABLE")
    expect(page.locator("#replay")).to_contain_text("RECORDED")
    shot(page, "c01_read_only_degraded.png", expect)

    # a wrong launch code: 403, no cookie, still read-only
    r = page.goto(base + "/session/start?code=" + random_code())
    assert r.status == 403 and "invalid or already used" in page.content()
    assert not [c for c in ctx.cookies() if c["name"] == "aegis_console"]

    # the real launch link: HttpOnly SameSite=Strict cookie that page JavaScript cannot read
    code = server["code"]
    _login(page, server, code)
    assert "aegis_console" not in page.evaluate("document.cookie")
    assert code not in page.content()
    cookie = [c for c in ctx.cookies() if c["name"] == "aegis_console"][0]
    assert cookie["httpOnly"] and cookie["sameSite"] == "Strict" and cookie["path"] == "/"
    expect(page.locator("#sess-end")).to_be_visible()

    # the same link a second time (browser history, another browser): refused, it was single-use
    other = browser.new_context()
    p2 = other.new_page()
    r = p2.goto(base + "/session/start?code=" + code)
    assert r.status == 403 and "already used" in p2.content()
    assert not [c for c in other.cookies() if c["name"] == "aegis_console"]
    other.close()

    # refresh keeps the session; the page re-reads it from the server
    page.reload()
    page.wait_for_load_state("networkidle")
    expect(page.locator("#sess")).to_contain_text("Operator session")
    shot(page, "c02_operator_session.png", expect)
    assert not errors, errors
    ctx.close()


def test_evidence_verification_and_tamper_rejection(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    errors = watch(page)
    _login(page, server)

    # the authentic shipped bundle: the independent verifier accepts it
    go(page, base, "#/evidence?open=DEMO-001-RELEASED")
    page.click("#do-verify")
    out = page.locator("#v-out")
    expect(out).to_contain_text("as expected", timeout=60_000)
    expect(out).not_to_contain_text("NOT as expected")
    expect(out).to_contain_text("Accepted")
    expect(out).to_contain_text("Exit code 0")
    shot(page, "c03_verify_authentic.png", expect)

    # a tampered disposable copy is rejected, the original accepted and byte-identical
    page.select_option("#t-mode", "rehash_chain")
    page.click("#do-tamper")
    t = page.locator("#t-out")
    expect(t.locator(".verdict")).to_contain_text("PASS", timeout=60_000)
    expect(t).to_contain_text("exit 1, rejected")
    expect(t).to_contain_text("exit 0, accepted")
    expect(t).to_contain_text("byte-identical before and after: yes")
    shot(page, "c04_tamper_rejected.png", expect)

    # the shipped tampered example must fail, and the console says that this is the expected outcome
    go(page, base, "#/evidence?open=VAL-001-TAMPERED")
    page.click("#do-verify")
    out = page.locator("#v-out")
    expect(out).to_contain_text("as expected", timeout=60_000)
    expect(out).to_contain_text("Rejected")
    expect(out).to_contain_text("Exit code 1")
    shot(page, "c05_verify_tampered_example.png", expect)
    assert not errors, errors
    ctx.close()


def test_oversized_malformed_and_unreachable_requests(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    errors = watch(page)
    _login(page, server)
    csrf = csrf_of(page)

    # oversized and malformed requests from the page itself: refused predictably, the session survives
    status = page.evaluate("""(csrf) => fetch('/api/lab/runs', {method: 'POST', headers: {'Content-Type': 'application/json',
        'X-Aegis-CSRF': csrf}, body: JSON.stringify({stop_after: 'created', pad: 'x'.repeat(300 * 1024)})}).then(r => r.status)""", csrf)
    assert status == 413
    bad = page.evaluate("""(csrf) => fetch('/api/lab/runs', {method: 'POST', headers: {'Content-Type': 'application/json',
        'X-Aegis-CSRF': csrf}, body: '{"stop_after": '}).then(async r => [r.status, await r.text()])""", csrf)
    assert bad[0] == 422 and "Traceback" not in bad[1]
    assert csrf_of(page) == csrf
    expect(page.locator("#sess")).to_contain_text("Operator session")
    runs = json.loads(ctx.request.get(base + "/api/runs").text())
    assert not [r for r in runs if r["id"].startswith("LAB-")]

    # live actions are refused with a meaningful reason when containers are unavailable (never a fake success)
    r = page.evaluate("""(csrf) => fetch('/api/lab/runs', {method: 'POST', headers: {'Content-Type': 'application/json',
        'X-Aegis-CSRF': csrf}, body: JSON.stringify({stop_after: 'created'})}).then(async r => [r.status, (await r.json()).detail])""", csrf)
    assert r[0] == 503 and "live execution unavailable" in r[1]

    # the backend becomes unreachable for one action: the UI says so and shows no result. A fresh tab: Chromium never reports
    # an upload the server cut short (the 413 above) as finished, which would hold off Playwright's network-idle wait.
    page = ctx.new_page()
    errors += watch(page)
    go(page, base, "#/evidence?open=DEMO-001-RELEASED")
    page.route("**/api/lab/bundles/*/verify", lambda route: route.abort())
    page.click("#do-verify")
    expect(page.locator("#toast")).to_contain_text("not reachable", timeout=10_000)
    expect(page.locator("#v-out")).not_to_contain_text("as expected")
    page.unroute("**/api/lab/bundles/*/verify")
    assert not [e for e in errors if "ERR_FAILED" not in e and "503" not in e], errors  # both provoked on purpose above
    ctx.close()


def test_end_session_returns_to_read_only(server, browser):
    base = server["base"]
    ctx = browser.new_context(viewport=DESKTOP)
    page = ctx.new_page()
    errors = watch(page)
    _login(page, server)
    csrf = csrf_of(page)
    page.click("#sess-end")
    expect(page.locator("#sess")).to_contain_text("Read-only")
    expect(page.locator("#sess-end")).to_be_hidden()
    status = page.evaluate("""(csrf) => fetch('/api/lab/runs/LAB-001/freeze', {method: 'POST', headers: {'X-Aegis-CSRF': csrf}})
        .then(r => r.status)""", csrf)
    assert status == 403
    page.reload()
    page.wait_for_load_state("networkidle")
    expect(page.locator("#sess")).to_contain_text("Read-only")
    go(page, base, "#/evidence?open=DEMO-001-RELEASED")
    expect(page.locator("#do-tamper")).to_be_disabled()
    shot(page, "c06_after_logout.png", expect)
    assert not errors, errors
    ctx.close()


@pytest.mark.parametrize("vp,prefix", [(DESKTOP, "c"), (PHONE, "cm")])
def test_main_pages_have_no_horizontal_overflow(server, browser, vp, prefix):
    base = server["base"]
    kw = {"device_scale_factor": 2, "is_mobile": True, "has_touch": True} if vp is PHONE else {}
    ctx = browser.new_context(viewport=vp, **kw)
    page = ctx.new_page()
    errors = watch(page)
    _login(page, server)
    for n, p in enumerate(("#/overview", "#/lab", "#/connections", "#/audit", "#/evidence", "#/experiments", "#/threat-model")):
        go(page, base, p)
        no_overflow(page)
        if vp is PHONE:
            shot(page, "%s%02d_%s.png" % (prefix, n + 1, p[2:].replace("-", "_")), expect)
    assert not errors, errors
    ctx.close()


@pytest.mark.parametrize("vp", [{"width": 1280, "height": 720}, {"width": 1366, "height": 768}, DESKTOP, PHONE])
def test_graph_caption_does_not_cover_the_drawing(server, browser, vp):
    """R4 regression: the caption under the isolation graph was an absolutely positioned overlay and covered the bottom row of
    components (Evidence verifier) on laptop screens. It must sit below the drawing and below the text view."""
    ctx = browser.new_context(viewport=vp)
    page = ctx.new_page()
    errors = watch(page)
    go(page, server["base"], "#/connections?view=topology")
    expect(page.locator("#gsvg")).to_be_visible()
    box = lambda sel: page.locator(sel).bounding_box()
    svg, foot, frame = box("#gsvg"), box(".gfoot"), box("#gframe")
    assert foot["y"] >= svg["y"] + svg["height"] - 1, "caption overlaps the graph: svg %s, caption %s" % (svg, foot)
    assert foot["y"] + foot["height"] <= frame["y"] + frame["height"] + 1, "caption outside its frame"
    assert svg["height"] >= 300, "graph squeezed to %s px" % svg["height"]
    page.click("#g-text")
    expect(page.locator("#gtext")).to_be_visible()
    text, foot = box("#gtext"), box(".gfoot")
    assert foot["y"] >= text["y"] + text["height"] - 1, "caption overlaps the text view"
    no_overflow(page)
    assert not errors, errors
    ctx.close()
