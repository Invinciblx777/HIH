"""Independent audit verifier and tamper test.

Reviewers run this on their own machine, with the exported audit log, the checkpoints they retained,
the broker's public key (pinned out of band) and, ideally, the signed terminal anchor:

    python -m aegis.verify_cli --bundle evidence_bundle/
    python -m aegis.verify_cli --audit audit.jsonl --checkpoints vault.jsonl \
        --pubkey <base64> [--anchor terminal_anchor.json] [--run-id RUN] [--expect-state RELEASED]

The default is fail-closed: a log is only reported valid when a signed terminal checkpoint (or an
equivalent retained anchor) proves it is complete. ``--allow-in-progress`` checks a run that has not
finished yet; the result then says ``terminal_verified: false`` and exits nonzero unless explicitly
accepted with ``--allow-in-progress``. Legacy bundles without terminal checkpoints can only be checked this way.

Tamper tests always operate on an in-memory copy and never modify stored logs.
"""
import argparse
import copy
import json
import sys
from pathlib import Path

from .audit import entry_hash, read_jsonl, verify

TAMPER_MODES = {
    "modify": "Change the outcome field of one attack.evaluated entry",
    "delete": "Delete one entry from the middle of the log",
    "reorder": "Swap two adjacent entries",
    "duplicate_seq": "Duplicate one entry so a sequence number repeats",
    "truncate": "Drop the final entries of the log; the full checkpoint vault is retained",
    "truncate_unprotected": "Drop the final entries and every checkpoint after freeze; no anchor retained",
    "truncate_vs_anchor": "Drop the final entries and every checkpoint after freeze; the signed terminal anchor is retained",
    "rehash": "Modify an entry and recompute every later hash (attacker without the signing key)",
    "drop_checkpoint": "Remove a middle checkpoint from the vault copy",
    "reorder_checkpoints": "Swap two adjacent checkpoints in the vault copy",
    "drop_terminal": "Remove the terminal checkpoint from the vault copy; no anchor retained",
    "forge_signature": "Corrupt the signature of the terminal checkpoint",
}


def tamper(entries, checkpoints, mode):
    e = copy.deepcopy(entries)
    cps = copy.deepcopy(checkpoints)
    use_anchor = True
    # prefer hiding a real finding: an unsafe_output entry rewritten as safe_output
    evaluated = [x for x in e if x["type"] == "attack.evaluated"]
    pick = (next((x for x in evaluated if x["data"]["outcome"] == "unsafe_output"), None)
            or next((x for x in evaluated if x["data"]["outcome"] != "safe_output"), None)
            or (evaluated[0] if evaluated else None))
    target = pick["seq"] if pick else len(e) // 2
    idx = target - 1
    if mode == "modify":
        e[idx]["data"]["outcome"] = "safe_output" if e[idx]["data"].get("outcome") != "safe_output" else "unsafe_output"
    elif mode == "delete":
        del e[idx]
    elif mode == "reorder":
        e[idx], e[idx + 1] = e[idx + 1], e[idx]
    elif mode == "duplicate_seq":
        e.insert(idx + 1, copy.deepcopy(e[idx]))
    elif mode == "truncate":
        e = e[:-3]
    elif mode == "truncate_unprotected":
        e = e[:-3]
        cps = [c for c in cps if c.get("reason") == "freeze"]
        use_anchor = False
    elif mode == "truncate_vs_anchor":
        e = e[:-3]
        cps = [c for c in cps if c.get("reason") == "freeze"]
    elif mode == "rehash":
        e[idx]["data"]["outcome"] = "safe_output" if e[idx]["data"].get("outcome") != "safe_output" else "unsafe_output"
        prev = e[idx]["prev"]
        for x in e[idx:]:
            x["prev"] = prev
            x["hash"] = entry_hash(x)
            prev = x["hash"]
    elif mode == "drop_checkpoint":
        del cps[len(cps) // 2 if len(cps) > 2 else 0]
    elif mode == "reorder_checkpoints":
        cps[0], cps[1] = cps[1], cps[0]
    elif mode == "drop_terminal":
        cps = [c for c in cps if c.get("reason") != "terminal"]
        use_anchor = False
    elif mode == "forge_signature":
        sig = cps[-1]["sig"]
        cps[-1]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        use_anchor = False
    else:
        raise ValueError("unknown tamper mode")
    return e, cps, target, use_anchor


def tamper_test(entries, checkpoints, public_b64, mode, anchor=None, run_id=None, expected_state=None):
    e, cps, target, use_anchor = tamper(entries, checkpoints, mode)
    res = verify(e, cps, public_b64, expect_sealed=mode not in ("truncate_unprotected", "truncate_vs_anchor"),
                 run_id=run_id, expected_state=expected_state, anchor=anchor if use_anchor else None)
    return {"mode": mode, "description": TAMPER_MODES[mode], "target_seq": target,
            "detected": not res["ok"], "verification": res}


def load_bundle(directory):
    d = Path(directory)
    meta = json.loads((d / "bundle.json").read_text()) if (d / "bundle.json").exists() else {}
    anchor = json.loads((d / "terminal_anchor.json").read_text()) if (d / "terminal_anchor.json").exists() else None
    return {"audit": d / "audit.jsonl", "checkpoints": d / "reviewer_checkpoints.jsonl",
            "pubkey": (d / "broker_public_key.b64").read_text().strip(), "anchor": anchor,
            "run_id": meta.get("run_id"), "state": meta.get("state")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bundle", help="evidence bundle directory (audit.jsonl, reviewer_checkpoints.jsonl, "
                                     "broker_public_key.b64, terminal_anchor.json, bundle.json)")
    ap.add_argument("--audit")
    ap.add_argument("--checkpoints")
    ap.add_argument("--pubkey", help="base64 Ed25519 public key, pinned out of band")
    ap.add_argument("--anchor", help="signed terminal checkpoint retained separately")
    ap.add_argument("--run-id")
    ap.add_argument("--expect-state", choices=["RELEASED", "FAILED"])
    ap.add_argument("--expect-events", type=int, help="number of audit entries the reviewer expects")
    ap.add_argument("--sealed", action="store_true", help="kept for compatibility; terminal evidence is now required by default")
    ap.add_argument("--allow-in-progress", action="store_true",
                    help="accept a log without terminal evidence (run not finished, or a legacy bundle); "
                         "completeness is then NOT established")
    a = ap.parse_args(argv)
    if a.bundle:
        b = load_bundle(a.bundle)
        audit, cps, pub, anchor = b["audit"], b["checkpoints"], b["pubkey"], b["anchor"]
        run_id, state = a.run_id or b["run_id"], a.expect_state or b["state"]
    else:
        if not (a.audit and a.checkpoints and a.pubkey):
            ap.error("give --bundle, or --audit, --checkpoints and --pubkey")
        audit, cps, pub = a.audit, a.checkpoints, a.pubkey
        anchor = json.loads(Path(a.anchor).read_text()) if a.anchor else None
        run_id, state = a.run_id, a.expect_state
    res = verify(read_jsonl(audit), read_jsonl(cps), pub, expect_sealed=not a.allow_in_progress, require_terminal=not a.allow_in_progress,
                 run_id=run_id, expected_state=state, expected_events=a.expect_events, anchor=anchor)
    print(json.dumps(res, indent=2))
    if res["ok"] and not res["terminal_verified"]:
        print("WARNING: in-progress check only; completeness of the log is NOT established.", file=sys.stderr)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
