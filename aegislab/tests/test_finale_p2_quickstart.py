"""Finale P2, finding F5: the console command that quickstart.sh prints (and runs with --serve) must actually start.

Before P2 it printed `AEGIS_DEMO_MODE=1 .venv/bin/uvicorn aegis.console:app ...`, which the console refuses at startup, so a
judge who copied the "Launch the console" line got a crash. quickstart.sh now points to scripts/start_prototype.sh.

The start test takes the CMD line verbatim from quickstart.sh, expands it as the script does, and runs it in a scratch copy
of the project tree (everything symlinked except scripts/ and var/, so the console's state goes to the scratch tree, never to
this checkout's var/console). A fake `podman` that always fails puts the console in degraded mode: no container is started.
"""
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
QS = ROOT / "scripts" / "quickstart.sh"


def printed_command(port: int) -> str:
    """The console command exactly as quickstart.sh builds and prints it ('Launch the console:  $CMD')."""
    lines = [l for l in QS.read_text().splitlines() if l.startswith("CMD=")]
    assert len(lines) == 1, lines
    out = subprocess.run(["bash", "-c", 'PORT=%d; AEGIS_VAR=/nonexistent; %s; printf %%s "$CMD"' % (port, lines[0])],
                         capture_output=True, text=True, check=True)
    return out.stdout


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_F5_quickstart_prints_and_serves_the_console_launcher_without_the_refused_flag():
    src = QS.read_text()
    assert printed_command(8500) == "scripts/start_prototype.sh --port 8500"
    assert 'echo "Launch the console:  $CMD"' in src
    serve = src[src.index('if [ "$SERVE" = 1 ]'):]
    assert 'exec scripts/start_prototype.sh --port "$PORT"' in serve
    code = [l for l in src.splitlines() if not l.lstrip().startswith("#")]
    assert not any("AEGIS_DEMO_MODE=1" in l for l in code), "the console refuses AEGIS_DEMO_MODE=1 at startup"
    assert not any(re.search(r"uvicorn\s+aegis\.console:app", l) for l in code), "the console is started by its own launcher"


@pytest.mark.skipif(not (ROOT / ".venv" / "bin" / "uvicorn").exists(), reason="needs the project virtualenv (.venv)")
def test_F5_the_printed_console_command_starts(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    for name in os.listdir(ROOT):
        if name not in ("scripts", "var"):
            (tree / name).symlink_to(ROOT / name)
    (tree / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts" / "start_prototype.sh", tree / "scripts" / "start_prototype.sh")
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "podman").write_text("#!/bin/sh\nexit 1\n")
    (fakebin / "podman").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env["PATH"] = "%s:%s" % (fakebin, os.environ["PATH"])
    port = free_port()
    cmd = printed_command(port)
    log = tmp_path / "console.log"
    with open(log, "w") as fh:
        proc = subprocess.Popen(["bash", "-c", cmd], cwd=tree, env=env, stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline, health = time.monotonic() + 90, None
        while time.monotonic() < deadline and proc.poll() is None:
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=2) as r:
                    health = r.status
                    break
            except OSError:
                time.sleep(0.5)
        out = log.read_text()
        assert health == 200, "console did not start (exit %s):\n%s" % (proc.poll(), out[-2000:])
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=5) as r:
            assert r.status == 200
        assert "Mode: DEGRADED" in out and "/session/start?code=" in out, out[-2000:]
        assert (tree / "var" / "console").is_dir(), "state went to the scratch tree"
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(5)
