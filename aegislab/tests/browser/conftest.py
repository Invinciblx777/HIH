"""Shared set-up for the browser end-to-end tests (Phase R3).

Two modules:
  test_console_browser_core.py  container-free: the console runs with a stand-in `podman` that always fails, so it is in its
                                degraded mode on every machine (CI included). Operator session, single-use launch link,
                                logout, evidence verification, tamper rejection, refresh, error handling, phone layout.
  test_console_browser.py       needs rootless Podman and the sandbox image: the whole live lifecycle in real containers.

Outcomes are never silently green. A missing dependency or runtime is reported as a skip whose reason starts with
"SKIPPED (dependency missing)" or "BLOCKED (runtime unavailable)"; scripts/run_browser_tests.sh turns those into the four
outcomes PASS / FAIL / SKIPPED / BLOCKED. With AEGIS_REQUIRE_BROWSER=1 a missing Playwright is a failure, and with
AEGIS_REQUIRE_PODMAN=1 a missing Podman or sandbox image is a failure.

Set-up (pinned): scripts/run_browser_tests.sh does all of it, or by hand
    python3 -m venv .venv-browser && .venv-browser/bin/pip install -r requirements-browser.txt
    .venv-browser/bin/playwright install chromium
    .venv-browser/bin/python -m pytest -q tests/browser
The console under test always runs from the repository's .venv (requirements.txt), not from the browser virtualenv.
"""
import contextlib
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHOTS = ROOT.parent / "docs" / "prototype" / "screenshots" / "r3"
CONSOLE_PY = ROOT / ".venv" / "bin" / "python"
IMAGE = "localhost/aegislab-sandbox:0.1"
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
SKIP_DEP = "SKIPPED (dependency missing): "
BLOCKED = "BLOCKED (runtime unavailable): "


def playwright_api():
    """The Playwright sync API, or a skip (or a failure with AEGIS_REQUIRE_BROWSER=1) when it is not installed."""
    try:
        from playwright import sync_api
    except ImportError:
        why = "playwright is not installed in %s; run scripts/run_browser_tests.sh" % sys.executable
        if os.environ.get("AEGIS_REQUIRE_BROWSER") == "1":
            pytest.fail("AEGIS_REQUIRE_BROWSER=1 but " + why, pytrace=False)
        pytest.skip(SKIP_DEP + why, allow_module_level=True)
    return sync_api


def console_python_missing():
    return None if CONSOLE_PY.exists() else "the repository .venv is missing (scripts/start_prototype.sh --check creates it)"


def podman_blocker():
    """Why live containers cannot run here, or None."""
    if not shutil.which("podman"):
        return "podman is not installed"
    try:
        if subprocess.run(["podman", "image", "exists", IMAGE], capture_output=True, timeout=20).returncode != 0:
            return "sandbox image %s is not built (scripts/start_prototype.sh builds it)" % IMAGE
    except (OSError, subprocess.TimeoutExpired):
        return "podman did not answer"
    return None


def require(blocker, prefix=BLOCKED, env="AEGIS_REQUIRE_PODMAN"):
    if blocker:
        if os.environ.get(env) == "1":
            pytest.fail("%s=1 but %s" % (env, blocker), pytrace=False)
        pytest.skip(prefix + blocker, allow_module_level=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def console_env(var, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_MODEL") and k not in ("AEGIS_DEMO_MODE", "AEGIS_CONSOLE_LAUNCH_CODE")}
    env.update(AEGIS_VAR=str(var), PYTHONDONTWRITEBYTECODE="1", **extra)
    return env


def issue_code(var):
    """A fresh single-use launch code for the console on `var`: exactly what scripts/start_prototype.sh does at start and
    with --link (aegis.lab_session.issue in the console's own interpreter)."""
    out = subprocess.run([str(CONSOLE_PY), "-c", "from aegis import lab_session; print(lab_session.issue())"], cwd=ROOT,
                         env=console_env(var), capture_output=True, text=True, timeout=60, check=True)
    return out.stdout.strip()


@contextlib.contextmanager
def running_console(var, env_extra=None, startup_timeout=90):
    """uvicorn aegis.console:app on a free loopback port with its own state directory, as the launcher starts it."""
    port = free_port()
    code = issue_code(var)
    log = open(var / "uvicorn.log", "w")
    proc = subprocess.Popen([str(CONSOLE_PY), "-m", "uvicorn", "aegis.console:app", "--host", "127.0.0.1", "--port", str(port),
                             "--no-server-header", "--log-level", "warning"], cwd=ROOT, env=console_env(var, **(env_extra or {})),
                            stdout=log, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    deadline = time.time() + startup_timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/lab/session", timeout=10) as r:
                if r.status == 200:
                    break
        except OSError:
            if proc.poll() is not None:
                break
            time.sleep(0.3)
    else:
        proc.kill()
        raise RuntimeError("console did not start: " + (var / "uvicorn.log").read_text()[-2000:])
    if proc.poll() is not None:
        raise RuntimeError("console exited: " + (var / "uvicorn.log").read_text()[-2000:])
    SHOTS.mkdir(parents=True, exist_ok=True)
    try:
        yield {"base": base, "code": code, "var": var, "proc": proc, "port": port}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def watch(page):
    """Collect page errors and console errors (refusals the test provokes on purpose are expected HTTP statuses)."""
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and not re.search(r"\b(403|409|413|422|429)\b", m.text) else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    return errors


def no_overflow(page):
    w = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
    assert w[0] <= w[1], "horizontal overflow %s" % w


def shot(page, name, expect):
    expect(page.locator("#toast")).not_to_have_class(re.compile(r"\bshow\b"), timeout=8_000)   # wait out a notice
    page.wait_for_timeout(400)   # let the entrance transitions finish
    page.screenshot(path=str(SHOTS / name), full_page=False)


def go(page, base, hashpath):
    page.goto(base + "/" + hashpath)
    page.wait_for_load_state("networkidle")


def csrf_of(page):
    return page.evaluate("fetch('/api/lab/session').then(r => r.json()).then(j => j.csrf || null)")


def random_code():
    return secrets.token_urlsafe(24)
