"""Phase 2: the audit verifier challenged through its command-line interface, on disposable bundle copies, plus a bounded
demonstration of what the trusted broker (and a holder of the signing key) can and cannot do."""
import base64
import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import audit, evidence, runs, runtime, store  # noqa: E402
from aegis.audit import checkpoint_hash, entry_hash, read_jsonl  # noqa: E402
from aegis.crypto import Signer  # noqa: E402
from aegis import verify_cli  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for v in ("AEGIS_VAULT", "AEGIS_ANCHORS"):
        monkeypatch.delenv(v, raising=False)


def released(run_id, tmp_path, unsafe=2, safe=4):
    runs.create_run(run_id, timing_bucket_ms=0)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state="RUNNING")
    for i in range(unsafe + safe):
        run.log("attack.evaluated", "broker", {"attack_id": "A%02d" % i, "outcome": "unsafe_output" if i < unsafe else "safe_output"})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED")
    run.checkpoint("seal")
    res = runs.release(run_id)
    out = tmp_path / ("bundle-" + run_id)
    evidence.export_bundle(run_id, out)
    return out, res


def cli(args):
    """Run the CLI as a separate process so the real exit status is what is asserted."""
    p = subprocess.run([sys.executable, "-m", "aegis.verify_cli"] + [str(a) for a in args], capture_output=True, text=True,
                       cwd=str(ROOT), env={"PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"}, timeout=60)
    try:
        body = json.loads(p.stdout)
    except ValueError:
        body = None
    return p.returncode, body, p.stderr


def rewrite(path, fn):
    rows = read_jsonl(path)
    rows = fn(rows)
    Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def clone(src, tmp_path, name):
    d = tmp_path / name
    shutil.copytree(src, d)
    for f in d.iterdir():
        f.chmod(0o644)  # the exported anchor is read-only; a tester's working copy is not
    return d


# ---------------------------------------------------------------- the strict verifier returns nonzero for each violation
def test_P2A01_valid_complete_bundle_passes_strict_and_reports_hash(tmp_path):
    b, res = released("A01", tmp_path)
    code, body, _ = cli(["--bundle", b, "--run-id", "A01", "--expect-state", "RELEASED", "--expect-events", len(read_jsonl(b / "audit.jsonl"))])
    assert code == 0 and body["ok"] and body["terminal_verified"] and body["terminal_hash"] == res["terminal_hash"]


MUTATIONS = {
    "modified_event": lambda d: rewrite(d / "audit.jsonl", lambda r: [dict(r[0], data=dict(r[0]["data"], x=1))] + r[1:] if False else
                                        [r[0], dict(r[1], data=dict(r[1]["data"], outcome="safe_output"))] + r[2:]),
    "deleted_event": lambda d: rewrite(d / "audit.jsonl", lambda r: r[:3] + r[4:]),
    "reordered_events": lambda d: rewrite(d / "audit.jsonl", lambda r: r[:3] + [r[4], r[3]] + r[5:]),
    "truncated_tail": lambda d: rewrite(d / "audit.jsonl", lambda r: r[:-2]),
    "duplicate_sequence": lambda d: rewrite(d / "audit.jsonl", lambda r: r[:4] + [r[3]] + r[4:]),
    "missing_terminal_in_vault": lambda d: (rewrite(d / "reviewer_checkpoints.jsonl", lambda r: [c for c in r if c["reason"] != "terminal"]),
                                            (d / "terminal_anchor.json").unlink()),
    "missing_anchor_and_truncated": lambda d: (rewrite(d / "audit.jsonl", lambda r: r[:-1]), (d / "terminal_anchor.json").unlink()),
    "invalid_signature": lambda d: rewrite(d / "reviewer_checkpoints.jsonl", lambda r: r[:-1] + [dict(r[-1], sig="A" * 86 + "==")]),
    "anchor_state_edited": lambda d: (d / "terminal_anchor.json").write_text(json.dumps(
        dict(json.loads((d / "terminal_anchor.json").read_text()), state="FAILED"), sort_keys=True)),
    "anchor_event_count_edited": lambda d: (d / "terminal_anchor.json").write_text(json.dumps(
        dict(json.loads((d / "terminal_anchor.json").read_text()), event_count=3), sort_keys=True)),
    "checkpoint_removed_from_middle": lambda d: rewrite(d / "reviewer_checkpoints.jsonl", lambda r: r[:1] + r[2:]),
    "entries_appended_after_terminal": lambda d: rewrite(d / "audit.jsonl", lambda r: r + [dict(r[-1], seq=len(r) + 1)]),
    "garbage_line": lambda d: (d / "audit.jsonl").write_text((d / "audit.jsonl").read_text() + "{not json\n"),
    "empty_log": lambda d: (d / "audit.jsonl").write_text(""),
    "log_is_not_objects": lambda d: (d / "audit.jsonl").write_text("[1,2,3]\n42\n"),
    "checkpoint_seq_is_text": lambda d: rewrite(d / "reviewer_checkpoints.jsonl", lambda r: [dict(c, seq="7") for c in r]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_P2A02_every_violation_makes_strict_verification_exit_nonzero_without_a_traceback(tmp_path, name):
    b, _ = released("A02", tmp_path)
    d = clone(b, tmp_path, "mut-" + name)
    MUTATIONS[name](d)
    code, body, err = cli(["--bundle", d, "--run-id", "A02", "--expect-state", "RELEASED"])
    assert code != 0, name
    assert "Traceback" not in err, err
    assert body is not None and body["ok"] is False


def test_P2A03_foreign_run_material_is_rejected(tmp_path):
    b1, _ = released("A03", tmp_path)
    b2, _ = released("A03B", tmp_path)
    # whole other bundle presented for run A03
    code, body, _ = cli(["--bundle", b2, "--run-id", "A03", "--expect-state", "RELEASED"])
    assert code != 0
    # foreign checkpoint inserted into the vault copy; foreign anchor swapped in
    d = clone(b1, tmp_path, "foreign-cp")
    rewrite(d / "reviewer_checkpoints.jsonl", lambda r: r[:-1] + read_jsonl(b2 / "reviewer_checkpoints.jsonl")[-1:])
    assert cli(["--bundle", d, "--run-id", "A03"])[0] != 0
    d = clone(b1, tmp_path, "foreign-anchor")
    shutil.copy(b2 / "terminal_anchor.json", d / "terminal_anchor.json")
    assert cli(["--bundle", d, "--run-id", "A03"])[0] != 0


def test_P2A04_in_progress_check_is_distinct_from_complete_verification(tmp_path):
    b, _ = released("A04", tmp_path)
    d = clone(b, tmp_path, "no-terminal")
    rewrite(d / "reviewer_checkpoints.jsonl", lambda r: [c for c in r if c["reason"] != "terminal"])
    (d / "terminal_anchor.json").unlink()
    strict = cli(["--bundle", d, "--run-id", "A04"])
    loose = cli(["--bundle", d, "--run-id", "A04", "--allow-in-progress"])
    assert strict[0] != 0 and strict[1]["terminal_verified"] is False
    assert loose[1]["terminal_verified"] is False and "NOT established" in loose[2]
    full = cli(["--bundle", b, "--run-id", "A04"])
    assert full[0] == 0 and full[1]["terminal_verified"] is True


def test_P2A05_legacy_format_is_only_accepted_in_progress_mode():
    legacy = ROOT / "evidence" / "DEMO-001"
    if not legacy.exists():
        pytest.skip("legacy bundle not present")
    assert cli(["--bundle", legacy])[0] != 0
    code, body, err = cli(["--bundle", legacy, "--allow-in-progress"])
    assert code == 0 and body["terminal_verified"] is False and "NOT established" in err


# ---------------------------------------------------------------- key pinning
def forged_bundle_with_own_key(src, tmp_path):
    """Attacker rebuilds the whole bundle, with weaker findings, signing with a key of their own and shipping that key."""
    d = clone(src, tmp_path, "forged")
    entries = read_jsonl(d / "audit.jsonl")
    for e in entries:
        if e["type"] == "attack.evaluated":
            e["data"]["outcome"] = "safe_output"
    prev = audit.GENESIS
    for e in entries:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    signer = Signer(tmp_path / "attacker.pem")
    cps, prev_cp = [], audit.GENESIS
    for i, (seq, reason, state) in enumerate([(2, "freeze", None), (len(entries), "terminal", "RELEASED")]):
        body = {"v": 2, "run_id": entries[0]["run_id"], "seq": seq, "head": entries[seq - 1]["hash"], "event_count": seq, "cp_seq": i + 1,
                "prev_cp": prev_cp, "ts": 1.0, "reason": reason, "key_id": signer.key_id}
        if state:
            body["state"] = state
        cp = dict(body, sig=signer.sign(body))
        prev_cp = checkpoint_hash(cp)
        cps.append(cp)
    (d / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
    (d / "reviewer_checkpoints.jsonl").write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cps))
    (d / "terminal_anchor.json").write_text(json.dumps(cps[-1], sort_keys=True))
    (d / "broker_public_key.b64").write_text(signer.public_b64() + "\n")
    return d


def test_P2A10_bundle_key_is_not_pinned_unless_the_reviewer_pins_it(tmp_path):
    b, _ = released("A10", tmp_path)
    real_key = (b / "broker_public_key.b64").read_text().strip()
    d = forged_bundle_with_own_key(b, tmp_path)
    unpinned = cli(["--bundle", d, "--run-id", "A10", "--expect-state", "RELEASED"])
    # Documented limitation: a bundle that carries its own key can be rebuilt end to end. The tool must say so.
    assert unpinned[0] == 0 and unpinned[1]["key_source"].startswith("bundle (NOT pinned")
    assert "not pinned" in unpinned[2].lower()
    pinned = cli(["--bundle", d, "--run-id", "A10", "--expect-state", "RELEASED", "--pubkey", real_key])
    assert pinned[0] != 0, "pinning the real broker key must reject a bundle signed by another key"
    assert pinned[1]["key_source"] == "pinned (--pubkey)"
    assert cli(["--bundle", b, "--run-id", "A10", "--pubkey", real_key])[0] == 0


def test_P2A11_recorded_terminal_hash_detects_a_rewrite_made_with_the_real_key(tmp_path):
    """Attacker holds the signing key and replaces every retained copy: this verifies unless the reviewer wrote down the
    terminal hash at release."""
    b, res = released("A11", tmp_path)
    key_pem = store.p("keys", "broker_ed25519.pem")
    entries = read_jsonl(b / "audit.jsonl")
    for e in entries:
        if e["type"] == "attack.evaluated":
            e["data"]["outcome"] = "safe_output"
    prev = audit.GENESIS
    for e in entries:
        e["prev"], prev = prev, None
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    signer = Signer(key_pem)
    body = {"v": 2, "run_id": "A11", "seq": len(entries), "head": entries[-1]["hash"], "event_count": len(entries), "cp_seq": 1,
            "prev_cp": audit.GENESIS, "ts": 1.0, "reason": "terminal", "key_id": signer.key_id, "state": "RELEASED"}
    cp = dict(body, sig=signer.sign(body))
    d = clone(b, tmp_path, "rewritten")
    (d / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
    (d / "reviewer_checkpoints.jsonl").write_text(json.dumps(cp, sort_keys=True) + "\n")
    (d / "terminal_anchor.json").write_text(json.dumps(cp, sort_keys=True))
    real_key = (b / "broker_public_key.b64").read_text().strip()
    args = ["--bundle", d, "--run-id", "A11", "--expect-state", "RELEASED", "--pubkey", real_key]
    assert cli(args)[0] == 0, "accepted limitation: key holder + all copies rewritten verifies without an out-of-band hash"
    code, body_, _ = cli(args + ["--expect-terminal-hash", res["terminal_hash"]])
    assert code != 0 and any("recorded at release" in f["issue"] for f in body_["findings"])
    assert cli(["--bundle", b, "--run-id", "A11", "--pubkey", real_key, "--expect-terminal-hash", res["terminal_hash"]])[0] == 0


# ---------------------------------------------------------------- trusted broker (accepted limitation, shown on a bounded fixture)
def test_P2A20_compromised_broker_can_sign_a_false_but_consistent_run(tmp_path):
    """The broker writes the audit entries and holds the key. A compromised broker can therefore record that unsafe outputs were
    safe, and the verifier cannot tell. This test documents the accepted limitation; it is not a defect to fix in the verifier."""
    runs.create_run("A20", timing_bucket_ms=0)
    runs.freeze("A20")
    run = runs.Run("A20")
    run.update(state="RUNNING")
    for i in range(6):  # what really happened: every attack produced unsafe output
        pass
    for i in range(6):  # what the compromised broker records instead
        run.log("attack.evaluated", "broker", {"attack_id": "A%02d" % i, "outcome": "safe_output", "canary_leaks": 0})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED")
    run.checkpoint("seal")
    runs.release("A20")
    out = tmp_path / "b20"
    evidence.export_bundle("A20", out)
    real_key = (out / "broker_public_key.b64").read_text().strip()
    code, body, _ = cli(["--bundle", out, "--run-id", "A20", "--expect-state", "RELEASED", "--pubkey", real_key])
    assert code == 0 and body["terminal_verified"]


def test_P2A21_the_result_gate_does_not_depend_on_a_participant_supplied_verdict(tmp_path):
    """A participant cannot supply a verdict: the oracle and outcome are computed in the broker from the model output."""
    assert runs.oracle_unsafe("x [UNSAFE-MARKER] y") is True
    assert runs.oracle_unsafe(base64.b64encode(b"zz [UNSAFE-MARKER]").decode()) is True
    assert runs.oracle_unsafe("harmless") is False
