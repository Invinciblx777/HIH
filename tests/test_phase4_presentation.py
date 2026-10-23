"""Phase 4: the presentation-mode demo (scripts/judge_demo.py) and its labelling.

P4D01 runs the real demo end to end (real rootless container, stub model, no network) and checks that it passes, that its
precomputed LLM section is labelled as precomputed, and that it never claims to have run a model itself. Needs podman and the sandbox image.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("podman") is None, reason="podman not available")
def test_P4D01_judge_demo_passes_and_labels_precomputed_evidence(tmp_path):
    rec = tmp_path / "transcript.json"
    res = subprocess.run([sys.executable, str(ROOT / "scripts" / "judge_demo.py"), "--state-dir", str(tmp_path / "state"), "--record", str(rec)],
                         capture_output=True, text=True, cwd=ROOT, timeout=300)
    assert res.returncode == 0, res.stdout[-1500:] + res.stderr[-500:]
    out = res.stdout
    assert "[PRECOMPUTED]" in out and "this demo does not run a model" in out
    assert "[HISTORICAL]" in out                      # the before-fix record is labelled as a recorded result
    assert "[FAIL]" not in out
    t = json.loads(rec.read_text())
    assert t["checks"].split("/")[0] == t["checks"].split("/")[1]
    assert all(set(x) == {"t", "kind", "text"} for x in t["lines"])
    assert [x["t"] for x in t["lines"]] == sorted(x["t"] for x in t["lines"])


def test_P4D02_original_demo_entry_point_is_unchanged_in_name_and_still_present():
    assert (ROOT / "scripts" / "security_demo.sh").exists() and (ROOT / "scripts" / "security_demo.py").exists()
    assert "PRESENTATION MODE" in (ROOT / "scripts" / "judge_demo.py").read_text()
