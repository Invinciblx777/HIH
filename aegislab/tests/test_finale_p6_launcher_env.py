"""Finale P6: the real-model console launcher scrubs inherited model settings but keeps AEGIS_MODELS_DIR.

Found by the offline-kit restore: the scrub loop matched the prefix AEGIS_MODEL, which also matches AEGIS_MODELS_DIR, so the
console only found the model in the default <repo>/../../../_models and failed for a kit restored anywhere else.
The test runs the launcher's own scrub line in bash. Container-free.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts/start_real_model_console.sh"


def _scrub_line():
    lines = [l for l in LAUNCHER.read_text().splitlines() if l.startswith("for k in $(env") and "unset" in l]
    assert len(lines) == 1, lines
    return lines[0].split("#")[0]


def test_scrub_keeps_models_dir_and_removes_model_settings():
    env = {"PATH": "/usr/bin:/bin", "AEGIS_MODELS_DIR": "/kit/models", "AEGIS_MODEL_BACKEND": "stub",
           "AEGIS_MODEL_BASE_URL": "http://203.0.113.1/", "AEGIS_MODEL_UNIX_SOCKET": "/tmp/x.sock"}
    r = subprocess.run(["bash", "-c", _scrub_line() + '\nenv | grep "^AEGIS_" | sort'], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["AEGIS_MODELS_DIR=/kit/models"]
