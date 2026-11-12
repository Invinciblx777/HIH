"""Finale P5: evaluation/check_finale_presentation.py catches a wrong number and a missing type label.

Container-free. Runs the checker's document checks on a temporary copy of the finale package (no re-derivation: that part
is covered by the checker run itself in the release gates), after changing exactly one thing.
"""
import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REL = ROOT.parent
spec = importlib.util.spec_from_file_location("cfp", ROOT / "evaluation" / "check_finale_presentation.py")
cfp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cfp)

pytestmark = pytest.mark.skipif(not (REL / cfp.CLAIMS).exists(), reason="finale package not built")


def copy_pkg(tmp_path):
    dst = tmp_path / "rel"
    shutil.copytree(REL / cfp.PKG, dst / cfp.PKG, ignore=shutil.ignore_patterns("src"))
    for f in ("README.md", "RC4_PACKAGE_HISTORICAL.md"):
        shutil.copy(REL / f, dst / f)
    return dst


def failures(root):
    return [r for r in cfp.run(root, rederive=False) if not r[1]]


def test_the_package_as_committed_passes_the_document_checks(tmp_path):
    assert failures(copy_pkg(tmp_path)) == []


def test_a_wrong_number_is_caught(tmp_path):
    root = copy_pkg(tmp_path)
    claims = json.loads((root / cfp.CLAIMS).read_text())["claims"]
    good = claims["e1_isolation"]["forms"]["trials"]          # e.g. "0 of 1040 isolation trials"
    bad = re.sub(r"(\d+)( isolation trials)", lambda m: str(int(m.group(1)) + 1) + m.group(2), good)
    qa = root / cfp.PKG / "FINALE_JUDGE_QA.md"
    t = qa.read_text()
    assert good in t
    qa.write_text(t.replace(good, bad, 1))
    bad_rows = failures(root)
    assert any("FINALE_JUDGE_QA.md" in r[0] and "not from claims_used_for_finale.json" in r[2] for r in bad_rows), bad_rows


def test_a_missing_type_label_is_caught(tmp_path):
    root = copy_pkg(tmp_path)
    claims = json.loads((root / cfp.CLAIMS).read_text())["claims"]
    lab = claims["timing_deadline_real"]["label"]               # "RE-MEASURED 11 Nov 2026"
    sc = root / cfp.PKG / "FINALE_SCRIPT.md"
    lines = sc.read_text().splitlines()
    form = claims["timing_deadline_real"]["forms"]["acc"]
    i = next(k for k, ln in enumerate(lines) if form in ln and lab in ln)
    lines[i] = re.sub(r"\s*[\[(]?RE-MEASURED 11 Nov(?: 2026)?[\])]?", "", lines[i])
    sc.write_text("\n".join(lines) + "\n")
    bad_rows = failures(root)
    assert any("FINALE_SCRIPT.md" in r[0] and "without its type label" in r[2] for r in bad_rows), bad_rows


def test_an_unknown_figure_in_a_caption_is_caught(tmp_path):
    root = copy_pkg(tmp_path)
    srt = root / cfp.TEXT_DOCS[3]
    t = srt.read_text().rstrip("\n").split("\n\n")
    t[1] = t[1] + " 99.7% safe"
    srt.write_text("\n\n".join(t) + "\n")
    assert any(".srt" in r[0] for r in failures(root))


def test_a_stale_claims_file_is_caught(tmp_path, monkeypatch):
    """A claims file that differs from what the checker derives now (here: the 10 Nov E2 control figure instead of the
    11 Nov one) fails the first check. The derivation itself is exercised by the checker run in the release gates."""
    root = copy_pkg(tmp_path)
    stored = json.loads((root / cfp.CLAIMS).read_text())
    stale = json.loads(json.dumps(stored))
    stale["claims"]["e2_control"]["forms"]["runs"] = "3 of 4 runs"
    (root / cfp.CLAIMS).write_text(json.dumps(stale))
    monkeypatch.setattr(cfp, "derive", lambda r: stored)
    rows = cfp.run(root, rederive=True)
    assert rows[0][1] is False and "e2_control" in rows[0][2]
