"""Finale P2: acknowledged source drift in evaluation/check_claims.py.

The saved Phase 3 experiment runs record the sha256 of the security-relevant sources they ran on. P2 changed some of those
files (aegis/runs.py, aegis/api.py, aegis/model_client.py, evaluation/llm_common.py, evaluation/llm_isolation.py), so the
"sources unchanged since the run" rows would fail. The change is acknowledged in a dated file, never by loosening the check:
the checker accepts a difference ONLY when the current hash equals the acknowledged new hash for the recorded old hash AND the
acknowledgement says, with a reason, that the change does not affect that experiment. Everything else still fails.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluation"))

import check_claims  # noqa: E402


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A scratch tree with one 'security-relevant source' whose recorded (old) content was changed once (new)."""
    root = tmp_path / "root"
    (root / "aegis").mkdir(parents=True)
    old, new = b"print('recorded')\n", b"print('changed by P2')\n"
    (root / "aegis" / "runs.py").write_bytes(new)
    (root / "aegis" / "same.py").write_bytes(b"x = 1\n")
    monkeypatch.setattr(check_claims, "ROOT", root)
    recorded = {"aegis/runs.py": h(old), "aegis/same.py": h(b"x = 1\n")}
    return root, recorded, h(old), h(new)


def ack_file(tmp_path, changes):
    f = tmp_path / "SOURCE_DRIFT.json"
    f.write_text(json.dumps({"changes": changes}))
    return f


def change(old, new, claims=None):
    return {"path": "aegis/runs.py", "old_sha256": old, "new_sha256": new, "commit": "0123456789abcdef",
            "reason": "test change",
            "claims": {"E1_canary_matrix": {"affects": False, "why": "the test change does not touch the measured path"}}
            if claims is None else claims}


def drift(recorded, files, exp="E1_canary_matrix"):
    return check_claims.source_drift(recorded, exp, check_claims.source_drift_acks(files))


def test_unacknowledged_drift_fails(tree, tmp_path):
    root, recorded, old, new = tree
    assert drift(recorded, []) == (["aegis/runs.py"], [])


def test_acknowledged_drift_is_accepted_only_for_the_exact_new_hash(tree, tmp_path):
    root, recorded, old, new = tree
    f = ack_file(tmp_path, [change(old, new)])
    assert drift(recorded, [f]) == ([], ["aegis/runs.py"])
    (root / "aegis" / "runs.py").write_bytes(b"print('changed by P2')\n#")  # one more byte: a further edit
    assert drift(recorded, [f]) == (["aegis/runs.py"], [])


def test_an_acknowledgement_for_a_different_recorded_hash_does_not_apply(tree, tmp_path):
    root, recorded, old, new = tree
    f = ack_file(tmp_path, [change(h(b"some other recorded version"), new)])
    assert drift(recorded, [f]) == (["aegis/runs.py"], [])


@pytest.mark.parametrize("claims", [
    {"E1_canary_matrix": {"affects": True, "why": "the change alters what E1 measured"}},
    {"E1_canary_matrix": {"affects": False, "why": "  "}},
    {"E1_canary_matrix": {"affects": "no", "why": "a string is not an explicit false"}},
    {"E2_pipeline_canary": {"affects": False, "why": "covers another experiment only"}},
    {},
])
def test_an_acknowledgement_that_does_not_clear_this_experiment_fails(tree, tmp_path, claims):
    root, recorded, old, new = tree
    f = ack_file(tmp_path, [change(old, new, claims)])
    assert drift(recorded, [f]) == (["aegis/runs.py"], [])


def test_a_missing_acknowledgement_file_acknowledges_nothing(tree, tmp_path):
    root, recorded, old, new = tree
    assert drift(recorded, [tmp_path / "absent.json"]) == (["aegis/runs.py"], [])


def test_the_acknowledgement_files_are_fixed_in_the_pinned_checker():
    # finale P3 added its own dated file (the P2 file is unchanged history); the list is still fixed here, never discovered
    assert [p.relative_to(ROOT).as_posix() for p in check_claims.SOURCE_DRIFT_FILES] == [
        "evidence/finale_rebaseline_2026-11-10/SOURCE_DRIFT.json", "evidence/finale_p3_2026-11-10/SOURCE_DRIFT.json"]


def test_on_this_tree_the_saved_runs_fail_without_the_acknowledgement_and_pass_with_it(monkeypatch):
    """The real Phase 3 evidence against the real sources: whatever drift exists is either acknowledged (rows pass) or the
    rows fail; with the acknowledgement files removed, every drifted experiment fails again."""
    if not (check_claims.P3 / "INDEX.json").exists():
        pytest.skip("no saved Phase 3 evidence in this tree")
    prov = check_claims.phase3_provenance()
    drifted = [p["experiment"] for p in prov if p["acknowledged"] or p["unacknowledged"]]
    if not drifted:
        pytest.skip("no source changed since the saved runs")
    rows, _ = check_claims.phase3_rows()
    src_rows = {r[0].split(":")[0]: r for r in rows if "security-relevant sources unchanged" in r[0]}
    for p in prov:
        assert src_rows[p["experiment"]][3] == (not p["unacknowledged"])
        if p["acknowledged"]:
            assert "recorded on sha256:" in src_rows[p["experiment"]][2] and "acknowledged change" in src_rows[p["experiment"]][2]
    monkeypatch.setattr(check_claims, "SOURCE_DRIFT_FILES", ())
    rows, _ = check_claims.phase3_rows()
    failing = {r[0].split(":")[0] for r in rows if "security-relevant sources unchanged" in r[0] and not r[3]}
    assert failing == set(drifted)
