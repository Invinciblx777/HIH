"""Finale P4, SHOULD 7: the reviewer's countersignature, and verify_cli --require-countersignature (both signatures)."""
import copy
import json
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import countersign, evidence, runs, runtime, store, verify_cli  # noqa: E402
from aegis.audit import GENESIS, entry_hash, read_jsonl  # noqa: E402
from aegis.crypto import Signer, commitment  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    for v in ("AEGIS_VAULT", "AEGIS_ANCHORS", "AEGIS_REVIEWER_KEY"):
        monkeypatch.delenv(v, raising=False)


def released_bundle(rid, dest):
    runs.create_run(rid, timing_bucket_ms=0)
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    run.log("attack.evaluated", "broker", {"attack_id": "A00", "outcome": "unsafe_output"})
    run.log("run.sealed", "control-plane", {"complete": True})
    run.update(state="SEALED", outcomes={"unsafe_output": 1})
    run.checkpoint("seal")
    store.append_jsonl(run.dir / "sealed/artifacts.jsonl", {
        "attack_id": "A00", "payload": "P", "nonce": "n", "verdict_in": {"verdict": "allow"}, "model_output": "x",
        "verdict_out": {"verdict": "allow"}, "final_output": "x", "outcome": "unsafe_output", "canary_leaks": [],
        "compute_ms": 1.0, "answered_ms": 1.0, "model_ms": 1.0, "defence_in_ms": 0.1})
    store.write_json(run.dir / "sealed/commitments.json", {"A00": commitment("n", "P")})
    rel = runs.release(rid)
    evidence.export_bundle(rid, dest)
    return rel


def cli(*args):
    return verify_cli.main([str(a) for a in args])


def pins(d):
    return (d / "broker_public_key.b64").read_text().strip(), countersign.Signer(countersign.reviewer_key_path()).public_b64()


def test_P4S01_release_countersigns_and_the_bundle_verifies_with_both_signatures(tmp_path):
    d = tmp_path / "b"
    rel = released_bundle("T-S01", d)
    assert rel["reviewer_countersignature"]["terminal_hash"] == rel["terminal_hash"]
    assert (d / "reviewer_countersignature.json").exists() and (d / "reviewer_public_key.b64").exists()
    bpub, rpub = pins(d)
    assert bpub != rpub
    assert cli("--bundle", d, "--run-id", "T-S01", "--expect-state", "RELEASED", "--pubkey", bpub,
               "--require-countersignature", "--reviewer-pubkey", rpub) == 0


def test_P4S02_missing_or_foreign_countersignature_is_refused(tmp_path):
    d = tmp_path / "b"
    released_bundle("T-S02", d)
    bpub, rpub = pins(d)
    base = ["--bundle", d, "--run-id", "T-S02", "--expect-state", "RELEASED", "--pubkey", bpub, "--require-countersignature"]
    other = Signer(tmp_path / "other.pem").public_b64()
    assert cli(*base, "--reviewer-pubkey", other) == 1
    (d / "reviewer_countersignature.json").unlink()
    assert cli(*base, "--reviewer-pubkey", rpub) == 1
    assert cli("--bundle", d, "--run-id", "T-S02", "--expect-state", "RELEASED", "--pubkey", bpub) == 0  # not required: as before


def test_P4S03_a_broker_key_forgery_verifies_alone_but_not_with_the_countersignature_required(tmp_path):
    """The documented limit (security_demo step 7): with the broker key and every retained copy replaced, a re-signed history
    verifies. With the reviewer's countersignature required it does not."""
    d = tmp_path / "b"
    released_bundle("T-S03", d)
    bpub, rpub = pins(d)
    audit = read_jsonl(d / "audit.jsonl")
    forged = copy.deepcopy(audit)
    i = next(k for k, e in enumerate(forged) if e["type"] == "attack.evaluated")
    forged[i]["data"]["outcome"] = "safe_output"
    prev = forged[i]["prev"]
    for e in forged[i:]:
        e["prev"] = prev
        e["hash"] = entry_hash(e)
        prev = e["hash"]
    k = runs.signer()
    body = {"v": 2, "run_id": "T-S03", "seq": len(forged), "head": forged[-1]["hash"], "event_count": len(forged), "cp_seq": 1,
            "prev_cp": GENESIS, "ts": time.time(), "reason": "terminal", "key_id": k.key_id, "state": "RELEASED"}
    anchor = dict(body, sig=k.sign(body))
    f = tmp_path / "forged"
    shutil.copytree(d, f)
    for x in f.iterdir():
        x.chmod(0o644)  # the copied anchor and countersignature are read-only (0444), like the originals
    (f / "audit.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in forged))
    (f / "reviewer_checkpoints.jsonl").write_text(json.dumps(anchor, sort_keys=True) + "\n")
    (f / "terminal_anchor.json").write_text(json.dumps(anchor))
    base = ["--bundle", f, "--run-id", "T-S03", "--expect-state", "RELEASED", "--pubkey", bpub]
    assert cli(*base) == 0  # the limit, still true without the countersignature
    assert cli(*base, "--require-countersignature", "--reviewer-pubkey", rpub) == 1


def test_P4S04_offline_countersigning_with_a_reviewer_held_key(tmp_path):
    d = tmp_path / "b"
    released_bundle("T-S04", d)
    bpub = (d / "broker_public_key.b64").read_text().strip()
    for n in ("reviewer_countersignature.json", "reviewer_public_key.b64"):
        (d / n).unlink()
    key = tmp_path / "mine" / "reviewer.pem"
    assert countersign.main(["--bundle", str(d), "--key", str(key), "--broker-pubkey", bpub, "--run-id", "T-S04",
                             "--expect-state", "RELEASED"]) == 0
    mine = Signer(key).public_b64()
    assert cli("--bundle", d, "--run-id", "T-S04", "--expect-state", "RELEASED", "--pubkey", bpub,
               "--require-countersignature", "--reviewer-pubkey", mine) == 0


def test_P4S05_offline_countersigning_refuses_a_bundle_that_does_not_verify(tmp_path):
    d = tmp_path / "b"
    released_bundle("T-S05", d)
    lines = (d / "audit.jsonl").read_text().splitlines()
    (d / "audit.jsonl").write_text("\n".join(lines[:-2]) + "\n")
    assert countersign.main(["--bundle", str(d), "--key", str(tmp_path / "k.pem"), "--run-id", "T-S05",
                             "--expect-state", "RELEASED"]) == 1


def test_P4S06_the_reviewer_key_is_separate_from_the_evidence_and_capability_keys(tmp_path):
    released_bundle("T-S06", tmp_path / "b")
    from aegis import captoken
    keys = {runs.signer().public_b64(), countersign.Signer(countersign.reviewer_key_path()).public_b64(), captoken.signer().public_b64()}
    assert len(keys) == 3
    assert (countersign.reviewer_key_path().stat().st_mode & 0o077) == 0
