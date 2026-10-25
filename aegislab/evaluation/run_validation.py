"""Validation run: audit tamper/truncation detection on real released runs + the access matrix.

    AEGIS_VAR=<scratch> python evaluation/run_validation.py --out evidence/validation_2026-10-22 [--runs 30] [--seed 1]

Writes <out>/audit_tamper.json and <out>/isolation_matrix.json. All tampering is applied to in-memory copies of logs
that were just produced by this script in AEGIS_VAR (never to the submitted evidence/ folder). The timing and real-model
experiments are separate scripts (timing_eval.py, model_experiments.py) because they have different cost and prerequisites.

Denominator note: the N runs share one synthetic attack pack, so their logs have the same structure; the repetition
shows determinism of detection across distinct signatures and checkpoints, not coverage of different workloads.
"""
import argparse
import copy
import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

from aegis import evidence, runtime, runs, store  # noqa: E402
from aegis.audit import read_jsonl, verify  # noqa: E402
from aegis.verify_cli import TAMPER_MODES, tamper_test  # noqa: E402
from revision import code_revision  # noqa: E402


def material(rid):
    run = runs.Run(rid)
    return {"entries": read_jsonl(run.dir / "audit.jsonl"), "cps": read_jsonl(store.vault_path(rid)),
            "anchor": store.read_json(store.anchor_path(rid)), "pub": runs.signer().public_b64(), "state": run.state, "id": rid}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    runtime.build_image(ROOT)
    ids = []
    for i in range(a.runs):
        rid = "VAL-%03d" % (i + 1)
        runs.create_run(rid, timing_bucket_ms=0, tags=["validation"])
        runs.freeze(rid)
        runs.start(rid, wait=True)
        runs.release(rid)
        ids.append(rid)
    mats = [material(r) for r in ids]
    res = {"started_at": t0, "kind": "audit tamper / truncation detection on real released runs",
           "runs": len(ids), "code_revision": code_revision(),
           "environment": {**runtime.environment(), "python": platform.python_version(), "platform": platform.platform()},
           "clean_runs_verify": sum(verify(m["entries"], m["cps"], m["pub"], expect_sealed=True, run_id=m["id"],
                                           expected_state=m["state"], anchor=m["anchor"])["ok"] for m in mats),
           "clean_runs_terminal_verified": sum(runs.verify_run(m["id"])["terminal_verified"] for m in mats),
           "entries_per_run": sorted({len(m["entries"]) for m in mats}), "checkpoints_per_run": sorted({len(m["cps"]) for m in mats}),
           "categories": {}}
    for mode, desc in TAMPER_MODES.items():
        det = sum(tamper_test(m["entries"], m["cps"], m["pub"], mode, anchor=m["anchor"], run_id=m["id"],
                              expected_state=m["state"])["detected"] for m in mats)
        res["categories"][mode] = {"description": desc, "trials": len(mats), "detected": det}
    # categories that need a second run or a wrong expectation
    extra = {}

    def count(label, desc, fn):
        extra[label] = {"description": desc, "trials": len(mats), "detected": sum(bool(fn(i, m)) for i, m in enumerate(mats))}
    count("foreign_checkpoint_in_vault", "terminal checkpoint replaced by the one from a different run (genuinely signed)",
          lambda i, m: not verify(m["entries"], m["cps"][:-1] + [mats[(i + 1) % len(mats)]["cps"][-1]], m["pub"], expect_sealed=True,
                                  run_id=m["id"], expected_state=m["state"])["ok"])
    count("foreign_anchor", "anchor from a different run supplied", lambda i, m: not verify(
        m["entries"], m["cps"], m["pub"], expect_sealed=True, run_id=m["id"], expected_state=m["state"],
        anchor=mats[(i + 1) % len(mats)]["anchor"])["ok"])
    count("other_run_substituted", "complete log+checkpoints of another run presented as this run", lambda i, m: not verify(
        mats[(i + 1) % len(mats)]["entries"], mats[(i + 1) % len(mats)]["cps"], m["pub"], expect_sealed=True, run_id=m["id"],
        expected_state=m["state"], anchor=mats[(i + 1) % len(mats)]["anchor"])["ok"])
    count("state_mismatch", "verifier told the run FAILED while evidence says RELEASED", lambda i, m: not verify(
        m["entries"], m["cps"], m["pub"], expect_sealed=True, run_id=m["id"], expected_state="FAILED", anchor=m["anchor"])["ok"])
    count("wrong_event_count", "reviewer expects a different number of entries", lambda i, m: not verify(
        m["entries"], m["cps"], m["pub"], expect_sealed=True, run_id=m["id"], expected_state=m["state"], anchor=m["anchor"],
        expected_events=len(m["entries"]) + 3)["ok"])
    count("sequence_gap", "an entry's seq field rewritten and re-hashed", lambda i, m: not verify(
        [dict(e, seq=99, hash=__import__("aegis.audit", fromlist=["x"]).entry_hash(dict(e, seq=99))) if k == 5 else e
         for k, e in enumerate(m["entries"])], m["cps"], m["pub"], expect_sealed=True, run_id=m["id"], expected_state=m["state"],
        anchor=m["anchor"])["ok"])
    count("extra_entry_after_terminal", "an entry appended after the terminal checkpoint", lambda i, m: not verify(
        m["entries"] + [dict(m["entries"][-1], seq=m["entries"][-1]["seq"] + 1, prev=m["entries"][-1]["hash"], hash="sha256:" + "1" * 64)],
        m["cps"], m["pub"], expect_sealed=True, run_id=m["id"], expected_state=m["state"], anchor=m["anchor"])["ok"])
    res["categories"].update(extra)
    # the original gap, measured with both the old rules and the new ones
    gap = {"description": "truncate last 3 entries; reviewer retained only the freeze checkpoint (the 0/30 case in the 15 Oct report)",
           "trials": len(mats)}
    gap["old_rules_detected (require_terminal=False)"] = sum(not verify(
        m["entries"][:-3], [c for c in m["cps"] if c["reason"] == "freeze"], m["pub"], require_terminal=False)["ok"] for m in mats)
    gap["new_rules_detected_fail_closed"] = sum(not verify(
        m["entries"][:-3], [c for c in m["cps"] if c["reason"] == "freeze"], m["pub"], expect_sealed=True, run_id=m["id"],
        expected_state=m["state"])["ok"] for m in mats)
    gap["new_rules_with_retained_anchor_detected"] = sum(not verify(
        m["entries"][:-3], [c for c in m["cps"] if c["reason"] == "freeze"], m["pub"], expect_sealed=True, run_id=m["id"],
        expected_state=m["state"], anchor=m["anchor"])["ok"] for m in mats)
    res["original_gap_case"] = gap
    # CLI level, on disk copies
    import shutil
    import tempfile
    from aegis.verify_cli import main as cli
    cli_res = {"bundles": 0, "genuine_accepted": 0, "tampered_rejected": 0, "tampered_total": 0}
    with tempfile.TemporaryDirectory() as td:
        for rid in ids[:10]:
            b = Path(td) / rid
            evidence.export_bundle(rid, b)
            cli_res["bundles"] += 1
            cli_res["genuine_accepted"] += cli(["--bundle", str(b)]) == 0
            for variant in ("truncate3", "truncate3_vault_stripped", "truncate3_vault_and_anchor_stripped", "modify_middle", "delete_anchor_only_ok"):
                c = Path(td) / (rid + "-" + variant)
                shutil.copytree(b, c)
                lines = (c / "audit.jsonl").read_text().splitlines()
                if variant.startswith("truncate3"):
                    (c / "audit.jsonl").write_text("\n".join(lines[:-3]) + "\n")
                if variant in ("truncate3_vault_stripped", "truncate3_vault_and_anchor_stripped"):
                    cps = read_jsonl(c / "reviewer_checkpoints.jsonl")
                    (c / "reviewer_checkpoints.jsonl").write_text(json.dumps(cps[0], sort_keys=True) + "\n")
                if variant == "truncate3_vault_and_anchor_stripped":
                    (c / "terminal_anchor.json").unlink()
                if variant == "modify_middle":
                    e = json.loads(lines[10]); e["data"]["tampered"] = 1; lines[10] = json.dumps(e, sort_keys=True)
                    (c / "audit.jsonl").write_text("\n".join(lines) + "\n")
                if variant == "delete_anchor_only_ok":
                    (c / "terminal_anchor.json").unlink()  # vault still holds the terminal: still valid, not a tamper
                    cli_res.setdefault("anchor_deleted_but_vault_intact_accepted", 0)
                    cli_res["anchor_deleted_but_vault_intact_accepted"] += cli(["--bundle", str(c)]) == 0
                    continue
                cli_res["tampered_total"] += 1
                cli_res["tampered_rejected"] += cli(["--bundle", str(c)]) == 1
    res["cli_level"] = cli_res
    # a published bundle for independent verification, and a deliberately tampered copy that must FAIL
    pub_dir = out / "bundles"
    for old in pub_dir.glob("VAL-001*"):
        shutil.rmtree(old)
    evidence.export_bundle(ids[0], pub_dir / ids[0])
    shutil.copytree(pub_dir / ids[0], pub_dir / (ids[0] + "_TAMPERED_truncated_last3"))
    t = pub_dir / (ids[0] + "_TAMPERED_truncated_last3")
    (t / "audit.jsonl").write_text("\n".join((t / "audit.jsonl").read_text().splitlines()[:-3]) + "\n")
    (t / "README_TAMPERED.txt").write_text("DELIBERATELY TAMPERED COPY (last 3 audit entries removed). Verification must FAIL.\n")
    res["published_bundles"] = {"genuine": "bundles/" + ids[0], "tampered_must_fail": "bundles/" + ids[0] + "_TAMPERED_truncated_last3",
                                "genuine_cli_exit": cli(["--bundle", str(pub_dir / ids[0])]), "tampered_cli_exit": cli(["--bundle", str(t)])}
    res["limits"] = [
        "an attacker who rewrites EVERY retained copy (vault, anchor store, reviewer's bundle) and holds the signing key forges a consistent history - not detected",
        "an attacker who controls the verifier or the pinned public key defeats verification",
        "the broker can sign false entries at write time; the chain proves integrity since signing, not truthfulness",
        "30 runs share one synthetic attack pack: the repeats test determinism across signatures, not different workloads",
        "'old_rules_detected' reproduces the 15 Oct 0/30 gap only for the freeze-only retention case",
    ]
    res["finished_at"] = time.time()
    res["wall_clock_s"] = round(res["finished_at"] - t0, 1)
    (out / "audit_tamper.json").write_text(json.dumps(res, indent=2, sort_keys=True))
    # access matrix, on a separate scratch state (container-free)
    import isolation_matrix as mx
    import tempfile as tf
    saved = store.VAR
    with tf.TemporaryDirectory() as td2:
        store.VAR = Path(td2)
        runs._signer = None
        rep = mx.run_matrix(out / "isolation_matrix.json")
    store.VAR = saved
    runs._signer = None
    summary = {"audit": {k: (v["detected"], v["trials"]) for k, v in res["categories"].items()}, "clean": res["clean_runs_verify"],
               "original_gap": gap, "cli": cli_res,
               "matrix": {k: rep[k] for k in ("cases_total", "cases_expect_deny", "denied_as_expected", "unauthorized_succeeded",
                                              "secret_marker_hits", "path_traversal_cases", "path_traversal_rejected")}}
    print(json.dumps(summary, indent=1))
    ok = (res["clean_runs_verify"] == len(ids) and all(v["detected"] == v["trials"] for v in res["categories"].values())
          and gap["new_rules_detected_fail_closed"] == len(ids) and cli_res["tampered_rejected"] == cli_res["tampered_total"]
          and rep["unauthorized_succeeded"] == 0 and rep["secret_marker_hits"] == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
