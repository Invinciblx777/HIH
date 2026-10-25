"""Adversarial tests for audit integrity and the terminal anchor.

No containers needed: the run lifecycle is driven through the real functions in aegis.runs with the
container runtime stubbed out. Every tamper operates on a deep copy or a tmp_path copy, never on the
submitted evidence.

Trust model under test: the verifier trusts (1) the pinned broker public key, (2) the reviewer-held copy
of the checkpoints and/or the signed terminal anchor, (3) its own code. The run directory is untrusted.
"""
import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import audit, evidence, runs, runtime, store  # noqa: E402
from aegis.audit import checkpoint_hash, read_jsonl, verify  # noqa: E402
from aegis.crypto import Signer  # noqa: E402
from aegis.verify_cli import TAMPER_MODES, main as verify_main, tamper_test  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:test")
    monkeypatch.setattr(runtime, "environment", lambda: {"test": True})
    for var in ("AEGIS_VAULT", "AEGIS_ANCHORS"):
        monkeypatch.delenv(var, raising=False)


def finished_run(run_id, evaluated=8, release=True):
    """Drive the real lifecycle without containers: CREATED -> FROZEN -> (broker work) -> SEALED -> RELEASED."""
    runs.create_run(run_id, timing_bucket_ms=0)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state="RUNNING")
    for i in range(evaluated):
        run.log("attack.evaluated", "broker", {"attack_id": "A%02d" % i, "outcome": "unsafe_output" if i % 2 else "safe_output"})
    run.log("model.reset", "control-plane", {"action": "container removed"})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED")
    run.checkpoint("seal")
    if release:
        runs.release(run_id)
    return run


def material(run_id):
    run = runs.Run(run_id)
    return {"entries": read_jsonl(run.dir / "audit.jsonl"), "cps": read_jsonl(store.vault_path(run_id)),
            "pub": runs.signer().public_b64(), "anchor": store.read_json(store.anchor_path(run_id)),
            "state": run.state, "run_id": run_id}


def check(m, entries=None, cps=None, **kw):
    kw.setdefault("run_id", m["run_id"])
    kw.setdefault("expected_state", m["state"])
    kw.setdefault("anchor", m["anchor"])
    return verify(m["entries"] if entries is None else entries, m["cps"] if cps is None else cps, m["pub"],
                  expect_sealed=True, **kw)


# 1 ---------------------------------------------------------------- valid, complete log
def test_01_valid_complete_log_and_terminal_fields():
    finished_run("T-OK")
    m = material("T-OK")
    r = check(m)
    assert r["ok"] and r["terminal_verified"] and r["terminal_state"] == "RELEASED" and r["anchor_checked"]
    t = m["cps"][-1]
    assert t["reason"] == "terminal" and t["state"] == "RELEASED" and t["run_id"] == "T-OK"
    assert t["seq"] == t["event_count"] == len(m["entries"]) and t["head"] == m["entries"][-1]["hash"]
    assert t["cp_seq"] == len(m["cps"]) and t["prev_cp"] == checkpoint_hash(m["cps"][-2])
    assert m["entries"][-1]["type"] == "run.released"
    assert m["anchor"] == t


def test_01b_anchor_is_read_only_and_outside_run_dir():
    finished_run("T-ANCH")
    path = store.anchor_path("T-ANCH")
    assert store.run_dir("T-ANCH") not in path.parents
    assert (path.stat().st_mode & 0o222) == 0
    assert store.vault_path("T-ANCH").exists() and store.run_dir("T-ANCH") not in store.vault_path("T-ANCH").parents


def test_01c_verify_run_endpoint_function_agrees():
    finished_run("T-VR")
    r = runs.verify_run("T-VR")
    assert r["ok"] and r["terminal_verified"]


# 2 ---------------------------------------------------------------- modification after sealing
@pytest.mark.parametrize("target", [3, 7, 12])
def test_02_modified_event(target):
    finished_run("T-MOD")
    m = material("T-MOD")
    e = copy.deepcopy(m["entries"])
    e[target - 1]["data"]["tampered"] = True
    r = check(m, entries=e)
    assert not r["ok"] and any("hash" in f["issue"] for f in r["findings"])


def test_02b_modified_and_rehashed_event_is_caught_by_signed_head():
    finished_run("T-REH")
    m = material("T-REH")
    e = copy.deepcopy(m["entries"])
    e[5]["data"]["outcome"] = "safe_output"
    prev = e[5]["prev"]
    for x in e[5:]:
        x["prev"] = prev
        x["hash"] = audit.entry_hash(x)
        prev = x["hash"]
    r = check(m, entries=e)
    assert not r["ok"] and any("head differs" in f["issue"] for f in r["findings"])


# 3 ---------------------------------------------------------------- event removed from the middle
def test_03_event_removed_from_middle():
    finished_run("T-DEL")
    m = material("T-DEL")
    e = copy.deepcopy(m["entries"])
    del e[len(e) // 2]
    r = check(m, entries=e)
    assert not r["ok"] and not r["chain_ok"]


# 4 ---------------------------------------------------------------- trailing events truncated
@pytest.mark.parametrize("drop", [1, 2, 3, 5])
def test_04_trailing_truncation_full_vault(drop):
    finished_run("T-TR")
    m = material("T-TR")
    r = check(m, entries=m["entries"][:-drop])
    assert not r["ok"] and any("truncation" in f["issue"] for f in r["findings"])


def test_04b_truncation_attacker_strips_vault_to_freeze_only_no_anchor_fails_closed():
    """The original 0/30 gap. Reviewer kept only the freeze checkpoint and has no anchor."""
    finished_run("T-GAP")
    m = material("T-GAP")
    freeze_only = [c for c in m["cps"] if c["reason"] == "freeze"]
    r = check(m, entries=m["entries"][:-3], cps=freeze_only, anchor=None)
    assert not r["ok"] and not r["terminal_verified"]
    assert any("no signed terminal checkpoint" in f["issue"] for f in r["findings"])


def test_04c_truncation_vs_retained_anchor_alone():
    finished_run("T-ANC2")
    m = material("T-ANC2")
    freeze_only = [c for c in m["cps"] if c["reason"] == "freeze"]
    r = check(m, entries=m["entries"][:-3], cps=freeze_only)
    assert not r["ok"] and any("truncation" in f["issue"] for f in r["findings"])
    # the untouched log still verifies from the same minimal material
    assert check(m, cps=freeze_only)["ok"]


def test_04d_dropping_the_final_released_entry_and_terminal_together():
    """Attacker removes the last entry and the terminal checkpoint from the vault copy; the anchor still holds."""
    finished_run("T-LAST")
    m = material("T-LAST")
    r = check(m, entries=m["entries"][:-1], cps=m["cps"][:-1])
    assert not r["ok"]
    assert not check(m, entries=m["entries"][:-1], cps=m["cps"][:-1], anchor=None)["ok"]  # no anchor: fail closed


def test_04e_extra_entries_appended_after_terminal():
    finished_run("T-EXTRA")
    m = material("T-EXTRA")
    e = copy.deepcopy(m["entries"])
    last = e[-1]
    forged = {"seq": last["seq"] + 1, "ts": 1.0, "run_id": "T-EXTRA", "type": "note", "actor": "x", "data": {},
              "prev": last["hash"]}
    forged["hash"] = audit.entry_hash(forged)
    r = check(m, entries=e + [forged])
    assert not r["ok"] and any("extra entries" in f["issue"] for f in r["findings"])


# 5 ---------------------------------------------------------------- checkpoints removed or reordered
def test_05_checkpoint_removed_from_middle():
    finished_run("T-CPD")
    m = material("T-CPD")
    assert len(m["cps"]) >= 3
    cps = copy.deepcopy(m["cps"])
    del cps[1]
    r = check(m, cps=cps)
    assert not r["ok"] and any("checkpoint index gap" in f["issue"] or "chain broken" in f["issue"] for f in r["findings"])


def test_05b_checkpoints_reordered():
    finished_run("T-CPR")
    m = material("T-CPR")
    cps = copy.deepcopy(m["cps"])
    cps[1], cps[2] = cps[2], cps[1]
    assert not check(m, cps=cps)["ok"]


def test_05c_terminal_checkpoint_removed_from_vault_without_anchor():
    finished_run("T-CPT")
    m = material("T-CPT")
    r = check(m, cps=m["cps"][:-1], anchor=None)
    assert not r["ok"] and not r["terminal_verified"]


def test_05d_terminal_checkpoint_not_last():
    finished_run("T-CPL")
    m = material("T-CPL")
    cps = copy.deepcopy(m["cps"])
    cps[-1], cps[-2] = cps[-2], cps[-1]
    assert not check(m, cps=cps, anchor=None)["ok"]


# 6 ---------------------------------------------------------------- checkpoint copied from a different run
def test_06_checkpoint_from_other_run_in_vault():
    finished_run("T-A")
    finished_run("T-B")
    a, b = material("T-A"), material("T-B")
    cps = copy.deepcopy(a["cps"])
    cps[-1] = copy.deepcopy(b["cps"][-1])  # genuinely signed by the same key, but for another run
    r = check(a, cps=cps, anchor=None)
    assert not r["ok"] and any("different run" in f["issue"] for f in r["findings"])


def test_06b_anchor_from_other_run():
    finished_run("T-A2")
    finished_run("T-B2")
    a, b = material("T-A2"), material("T-B2")
    r = check(a, anchor=b["anchor"])
    assert not r["ok"] and any("different run" in f["issue"] for f in r["findings"])


def test_06c_whole_other_run_substituted():
    """Log and checkpoints of run B presented as run A: caught because the verifier is told the run id."""
    finished_run("T-A3")
    finished_run("T-B3")
    a, b = material("T-A3"), material("T-B3")
    r = verify(b["entries"], b["cps"], b["pub"], expect_sealed=True, run_id="T-A3", expected_state="RELEASED",
               anchor=b["anchor"])
    assert not r["ok"]


# 7 ---------------------------------------------------------------- invalid signatures
def test_07_terminal_signature_forged():
    finished_run("T-SIG")
    m = material("T-SIG")
    cps = copy.deepcopy(m["cps"])
    cps[-1]["sig"] = ("A" if cps[-1]["sig"][0] != "A" else "B") + cps[-1]["sig"][1:]
    r = check(m, cps=cps, anchor=None)
    assert not r["ok"] and any("signature invalid" in f["issue"] for f in r["findings"])


def test_07b_terminal_body_edited_keeps_old_signature():
    finished_run("T-SIG2")
    m = material("T-SIG2")
    cps = copy.deepcopy(m["cps"])
    cps[-1]["state"] = "FAILED"
    assert not check(m, cps=cps, anchor=None)["ok"]


def test_07c_signed_by_a_different_key(tmp_path):
    finished_run("T-KEY")
    m = material("T-KEY")
    other = Signer(tmp_path / "other.pem")
    r = verify(m["entries"], m["cps"], other.public_b64(), expect_sealed=True, run_id="T-KEY")
    assert not r["ok"]


def test_07d_forged_anchor_signature():
    finished_run("T-SIG3")
    m = material("T-SIG3")
    bad = dict(m["anchor"], sig=("A" if m["anchor"]["sig"][0] != "A" else "B") + m["anchor"]["sig"][1:])
    r = check(m, anchor=bad)
    assert not r["ok"]


# 8 ---------------------------------------------------------------- missing or inconsistent terminal
def test_08_missing_terminal_fails_closed_even_for_an_untouched_log():
    finished_run("T-MISS")
    m = material("T-MISS")
    r = check(m, cps=[c for c in m["cps"] if c["reason"] != "terminal"], anchor=None)
    assert not r["ok"] and not r["terminal_verified"]


def test_08b_empty_checkpoints_fail():
    finished_run("T-EMPTY")
    m = material("T-EMPTY")
    assert not check(m, cps=[], anchor=None)["ok"]
    assert not check(m, cps=[], anchor=None, require_terminal=False)["ok"]


def test_08c_terminal_inconsistent_with_log_head():
    finished_run("T-INC")
    m = material("T-INC")
    e = copy.deepcopy(m["entries"])
    e[-1]["data"]["x"] = 1  # last entry no longer matches signed head
    assert not check(m, entries=e)["ok"]


def test_08d_two_terminal_checkpoints():
    finished_run("T-TWO")
    m = material("T-TWO")
    cps = copy.deepcopy(m["cps"]) + [copy.deepcopy(m["cps"][-1])]
    assert not check(m, cps=cps, anchor=None)["ok"]


def test_08e_anchor_disagrees_with_vault_terminal():
    finished_run("T-DIS")
    m = material("T-DIS")
    other = dict(m["anchor"])
    other["ts"] = other["ts"] + 1  # different body, signature now invalid -> anchor rejected
    assert not check(m, anchor=other)["ok"]


def test_08f_terminal_checkpoint_cannot_be_issued_twice():
    run = finished_run("T-ONCE")
    with pytest.raises(runs.GateError):
        run.terminal_checkpoint("RELEASED")


def test_08g_verify_run_fails_when_anchor_store_entry_missing():
    finished_run("T-NOANC")
    p = store.anchor_path("T-NOANC")
    p.chmod(0o644)
    p.unlink()
    r = runs.verify_run("T-NOANC")
    assert not r["ok"] and any("anchor missing" in f["issue"] for f in r["findings"])


def test_08h_verify_run_detects_vault_truncation_on_disk():
    finished_run("T-VT")
    vault = store.vault_path("T-VT")
    lines = vault.read_text().splitlines()
    vault.write_text("\n".join(lines[:-1]) + "\n")  # drop terminal from the vault, anchor store still has it
    r = runs.verify_run("T-VT")
    assert not r["ok"]


def test_08i_verify_run_detects_log_truncation_on_disk():
    finished_run("T-LT")
    log = store.run_dir("T-LT") / "audit.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-3]) + "\n")
    assert not runs.verify_run("T-LT")["ok"]


# 9 ---------------------------------------------------------------- duplicate or discontinuous sequence numbers
def test_09_duplicate_sequence_number():
    finished_run("T-DUP")
    m = material("T-DUP")
    e = copy.deepcopy(m["entries"])
    e.insert(6, copy.deepcopy(e[5]))
    r = check(m, entries=e)
    assert not r["ok"] and any("sequence" in f["issue"] for f in r["findings"])


def test_09b_sequence_gap():
    finished_run("T-GAP2")
    m = material("T-GAP2")
    e = copy.deepcopy(m["entries"])
    e[4]["seq"] = 99
    e[4]["hash"] = audit.entry_hash(e[4])
    assert not check(m, entries=e)["ok"]


def test_09c_entry_from_another_run_spliced_in():
    finished_run("T-S1")
    finished_run("T-S2")
    a, b = material("T-S1"), material("T-S2")
    e = copy.deepcopy(a["entries"])
    e[8] = copy.deepcopy(b["entries"][8])
    assert not check(a, entries=e)["ok"]


def test_09d_expected_event_count_enforced():
    finished_run("T-CNT")
    m = material("T-CNT")
    assert check(m, expected_events=len(m["entries"]))["ok"]
    assert not check(m, expected_events=len(m["entries"]) + 1)["ok"]


# 10 --------------------------------------------------------------- lifecycle state vs terminal evidence
def test_10_recorded_state_differs_from_terminal_state():
    finished_run("T-ST")
    m = material("T-ST")
    r = check(m, expected_state="FAILED")
    assert not r["ok"] and any("differs from the run's recorded state" in f["issue"] for f in r["findings"])


def test_10b_run_json_says_sealed_but_terminal_exists():
    finished_run("T-ST2")
    run = runs.Run("T-ST2")
    run.update(state="SEALED")
    assert runs.verify_run("T-ST2")["ok"] is True  # SEALED is checked in-progress; terminal not demanded
    assert not runs.verify_run("T-ST2")["terminal_verified"]


def test_10c_run_json_says_released_without_terminal():
    run = finished_run("T-ST3", release=False)
    run.update(state="RELEASED")  # attacker flips state without going through release()
    r = runs.verify_run("T-ST3")
    assert not r["ok"] and not r["terminal_verified"]


def test_10d_failed_run_gets_failed_terminal_checkpoint():
    runs.create_run("T-FAIL", timing_bucket_ms=0)
    runs.freeze("T-FAIL")
    run = runs.Run("T-FAIL")
    run.update(state="RUNNING")
    # emulate the broker's failure path
    run.log("run.failed", "control-plane", {"error": "RuntimeFailure"}, checkpoint=False, close=True)
    run.update(state="FAILED")
    run.terminal_checkpoint("FAILED")
    r = runs.verify_run("T-FAIL")
    assert r["ok"] and r["terminal_state"] == "FAILED"
    with pytest.raises(runs.GateError):
        runs.release("T-FAIL")


def test_10e_final_entry_must_match_state():
    finished_run("T-ST4")
    m = material("T-ST4")
    # sign a FAILED terminal over a log that ends in run.released
    s = runs.signer()
    from aegis.audit import GENESIS
    body = {"v": 2, "run_id": "T-ST4", "seq": len(m["entries"]), "head": m["entries"][-1]["hash"],
            "event_count": len(m["entries"]), "cp_seq": len(m["cps"]), "prev_cp": m["cps"][-1]["prev_cp"],
            "ts": 1.0, "reason": "terminal", "key_id": s.key_id, "state": "FAILED"}
    cps = copy.deepcopy(m["cps"])
    cps[-1] = dict(body, sig=s.sign(body))
    r = check(m, cps=cps, anchor=None, expected_state=None)
    assert not r["ok"] and any("does not match the final lifecycle event" in f["issue"] for f in r["findings"])


# lifecycle behaviours ----------------------------------------------------------------------------
def test_chain_closed_after_terminal_late_events_go_to_side_file():
    run = finished_run("T-LATE")
    before = len(read_jsonl(run.dir / "audit.jsonl"))
    r = runs.Run("T-LATE")
    r.log("policy.denied", "observer", {"op": "read_artifacts"}, monitor={"summary": "denied"})
    assert len(read_jsonl(run.dir / "audit.jsonl")) == before
    assert len(read_jsonl(run.dir / "post_terminal.jsonl")) == 1
    assert runs.verify_run("T-LATE")["ok"]


def test_two_run_objects_do_not_fork_the_chain():
    runs.create_run("T-FORK", timing_bucket_ms=0)
    a, b = runs.Run("T-FORK"), runs.Run("T-FORK")
    for i in range(6):
        (a if i % 2 else b).log("note", "x", {"i": i})
    entries = read_jsonl(a.dir / "audit.jsonl")
    assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
    assert verify(entries, [], "x", require_terminal=False)["chain_ok"]


def test_release_requires_sealed_and_verified_chain():
    run = finished_run("T-REL", release=False)
    log = run.dir / "audit.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n")  # truncate before release
    with pytest.raises(runs.GateError):
        runs.release("T-REL")
    assert runs.Run("T-REL").state == "SEALED"


# CLI and bundle -------------------------------------------------------------------------------------
def test_bundle_export_and_cli_roundtrip(tmp_path):
    finished_run("T-BUN")
    out = tmp_path / "bundle"
    info = evidence.export_bundle("T-BUN", out)
    assert info["state"] == "RELEASED"
    assert verify_main(["--bundle", str(out)]) == 0
    with pytest.raises(FileExistsError):
        evidence.export_bundle("T-BUN", out)  # never overwrites


def test_cli_rejects_tampered_bundle_copy_and_original_is_untouched(tmp_path, capsys):
    finished_run("T-BUN2")
    good = tmp_path / "good"
    evidence.export_bundle("T-BUN2", good)
    bad = tmp_path / "bad"
    shutil.copytree(good, bad)
    lines = (bad / "audit.jsonl").read_text().splitlines()
    (bad / "audit.jsonl").write_text("\n".join(lines[:-3]) + "\n")
    assert verify_main(["--bundle", str(bad)]) == 1
    assert verify_main(["--bundle", str(good)]) == 0
    # attacker also strips the vault copy to the freeze checkpoint: the anchor still catches it
    cps = read_jsonl(bad / "reviewer_checkpoints.jsonl")
    (bad / "reviewer_checkpoints.jsonl").write_text(json.dumps(cps[0], sort_keys=True) + "\n")
    assert verify_main(["--bundle", str(bad)]) == 1
    # and if the anchor is deleted as well, the verifier fails closed
    (bad / "terminal_anchor.json").unlink()
    assert verify_main(["--bundle", str(bad)]) == 1
    capsys.readouterr()


def test_cli_in_progress_flag_is_explicit(tmp_path, capsys):
    finished_run("T-BUN3")
    d = tmp_path / "b"
    evidence.export_bundle("T-BUN3", d)
    (d / "terminal_anchor.json").unlink()
    cps = [c for c in read_jsonl(d / "reviewer_checkpoints.jsonl") if c["reason"] != "terminal"]
    (d / "reviewer_checkpoints.jsonl").write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cps))
    assert verify_main(["--bundle", str(d)]) == 1
    capsys.readouterr()
    assert verify_main(["--bundle", str(d), "--allow-in-progress"]) == 0
    assert "NOT established" in capsys.readouterr().err


@pytest.mark.parametrize("mode", sorted(TAMPER_MODES))
def test_every_tamper_mode_is_detected_on_a_released_run(mode):
    finished_run("T-ALL")
    m = material("T-ALL")
    res = tamper_test(m["entries"], m["cps"], m["pub"], mode, anchor=m["anchor"], run_id="T-ALL",
                      expected_state="RELEASED")
    assert res["detected"], res["verification"]["findings"]


def test_untampered_copy_passes_in_the_tamper_harness_baseline():
    finished_run("T-BASE")
    m = material("T-BASE")
    assert check(m)["ok"]


def test_original_submission_evidence_fails_closed_without_terminal_evidence():
    """The submitted DEMO-001 bundle predates terminal checkpoints. Strict mode must refuse it; the explicit
    in-progress mode still validates chain and checkpoint consistency (read only, no writes)."""
    d = ROOT / "evidence" / "DEMO-001"
    if not d.exists():
        pytest.skip("submitted evidence bundle not present")
    pub = (d / "broker_public_key.b64").read_text().strip()
    e, c = read_jsonl(d / "audit.jsonl"), read_jsonl(d / "reviewer_checkpoints.jsonl")
    assert not verify(e, c, pub, expect_sealed=True)["ok"]
    r = verify(e, c, pub, expect_sealed=True, require_terminal=False)
    assert r["ok"] and not r["terminal_verified"]


def test_chain_is_closed_atomically_with_the_final_event():
    """No entry can land between run.released and the terminal checkpoint, even with writers racing the release."""
    import threading
    runs.create_run("T-RACE", timing_bucket_ms=0)
    runs.freeze("T-RACE")
    run = runs.Run("T-RACE")
    run.update(state="SEALED")
    run.checkpoint("seal")
    stop = threading.Event()

    def spam():
        r = runs.Run("T-RACE")
        while not stop.is_set():
            r.log("policy.denied", "observer", {"op": "read_artifacts"}, checkpoint=False)

    ts = [threading.Thread(target=spam) for _ in range(4)]
    [t.start() for t in ts]
    try:
        runs.release("T-RACE")
    finally:
        stop.set()
        [t.join() for t in ts]
    entries = read_jsonl(run.dir / "audit.jsonl")
    assert entries[-1]["type"] == "run.released"
    assert runs.verify_run("T-RACE")["ok"]
    assert runs.Run("T-RACE").state == "RELEASED"


def test_closed_chain_refuses_appends_and_terminal_needs_close():
    runs.create_run("T-CLOSE", timing_bucket_ms=0)
    run = runs.Run("T-CLOSE")
    run.update(state="FAILED")
    with pytest.raises(runs.GateError):
        run.terminal_checkpoint("FAILED")  # final event not logged with close=True yet
    run.log("run.failed", "control-plane", {}, checkpoint=False, close=True)
    assert run.audit.append("note", "x", {}) is None
    run.terminal_checkpoint("FAILED")
    assert runs.verify_run("T-CLOSE")["ok"]
