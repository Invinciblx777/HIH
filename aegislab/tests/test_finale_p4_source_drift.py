"""Finale P4: the stricter acknowledgement ("affects": true + "superseded_by"), the third fixed acknowledgement file, and the
rule that the current real-model set (Part F) may not rely on any acknowledgement."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluation"))

import check_claims  # noqa: E402

K = "aegis/runs.py"
CUR = hashlib.sha256((ROOT / K).read_bytes()).hexdigest()
OLD = "0" * 64


def ack(claim):
    return {K: [{"path": K, "old_sha256": OLD, "new_sha256": CUR, "claims": {"E2_pipeline_canary": claim}}]}


def remeasurement(tmp_path, recorded):
    d = tmp_path / "llm"
    (d / "run1").mkdir(parents=True)
    (d / "INDEX.json").write_text(json.dumps([{"experiment": "E2_pipeline_canary", "dir": "run1"}]))
    (d / "run1" / "result.json").write_text(json.dumps({"source_sha256": recorded}))
    return d


def test_P4D01_affects_true_without_a_re_measurement_is_not_accepted():
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", ack({"affects": True, "why": "it does"})) == ([K], [])


def test_P4D02_affects_true_is_accepted_only_with_a_re_measurement_on_the_current_code(tmp_path):
    good = remeasurement(tmp_path, {K: CUR})
    kinds = {}
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", ack({"affects": True, "why": "it does", "superseded_by": str(good)}), kinds=kinds) == ([], [K])
    assert kinds[K].startswith("re-measured in ")
    stale = remeasurement(tmp_path / "s", {K: "1" * 64})  # the re-measurement itself drifted: refused
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", ack({"affects": True, "why": "it does", "superseded_by": str(stale)})) == ([K], [])
    other = remeasurement(tmp_path / "o", {K: CUR})
    (other / "INDEX.json").write_text(json.dumps([{"experiment": "E4_injection_output_isolation", "dir": "run1"}]))  # another experiment
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", ack({"affects": True, "why": "it does", "superseded_by": str(other)})) == ([K], [])
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", ack({"affects": True, "why": " ", "superseded_by": str(good)})) == ([K], [])


def test_P4D03_a_further_edit_after_the_acknowledgement_still_fails(tmp_path):
    good = remeasurement(tmp_path, {K: CUR})
    a = ack({"affects": True, "why": "it does", "superseded_by": str(good)})
    a[K][0]["new_sha256"] = "2" * 64
    assert check_claims.source_drift({K: OLD}, "E2_pipeline_canary", a) == ([K], [])


def test_P4D04_the_p4_file_uses_only_the_two_accepted_kinds_and_names_its_re_measurements():
    f = check_claims.SOURCE_DRIFT_FILES[2]
    if not f.exists():
        pytest.skip("no finale P4 acknowledgement file")
    d = json.loads(f.read_text())
    for c in d["changes"]:
        for exp, v in c["claims"].items():
            assert len(v["why"]) > 60
            if v["affects"]:
                assert v["superseded_by"].startswith("evidence/finale_p4_2026-11-11/"), (c["path"], exp)
            assert exp not in ("E2_pipeline_canary", "E4_injection_output_isolation", "E5_failure_handling", "model_server_hardening") or v["affects"] is True


def test_P4D05_the_current_set_part_f_may_not_rely_on_an_acknowledgement(monkeypatch):
    fake = [("E1_canary_matrix: security-relevant sources unchanged since the run", "d", "recorded on x; acknowledged change, does not affect E1: a", True)]
    monkeypatch.setattr(check_claims, "phase3_rows", lambda base=None, report=None: (fake, {}))
    if not (check_claims.P4F / "INDEX.json").exists():
        pytest.skip("no finale P4 real-model evidence")
    rows, _ = check_claims.finale_p4_rows()
    src = [r for r in rows if "security-relevant sources" in r[0]]
    assert src and not src[0][3]


def test_P4D06_latest_real_model_is_the_p4_set_when_present(monkeypatch, tmp_path):
    (tmp_path / "llm").mkdir()
    (tmp_path / "llm" / "INDEX.json").write_text("[]")
    monkeypatch.setattr(check_claims, "P4F", tmp_path / "llm")
    base, label = check_claims.latest_real_model()
    assert base == tmp_path / "llm" and "11 Nov" in label
