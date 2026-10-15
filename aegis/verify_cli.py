"""Independent audit verifier and tamper test.

Reviewers run this on their own machine with the exported audit log, the
checkpoints they retained, and the broker's public key:

    python -m aegis.verify_cli --audit audit.jsonl --checkpoints vault.jsonl \
        --pubkey <base64> --sealed

Tamper tests always operate on an in-memory copy and never modify stored logs.
"""
import argparse
import copy
import json
import sys

from .audit import read_jsonl, verify

TAMPER_MODES = {
    "modify": "Change the outcome field of one attack.evaluated entry",
    "delete": "Delete one entry from the middle of the log",
    "reorder": "Swap two adjacent entries",
    "truncate": "Drop the final entries of the log (reviewer holds the seal checkpoint)",
    "truncate_unprotected": "Drop the final entries when the reviewer kept only the freeze checkpoint",
    "rehash": "Modify an entry and recompute every later hash (attacker without the signing key)",
}


def tamper(entries, checkpoints, mode):
    e = copy.deepcopy(entries)
    cps = copy.deepcopy(checkpoints)
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
    elif mode == "truncate":
        e = e[:-3]
    elif mode == "truncate_unprotected":
        e = e[:-3]
        cps = [c for c in cps if c.get("reason") == "freeze"]
    elif mode == "rehash":
        from .audit import entry_hash
        e[idx]["data"]["outcome"] = "safe_output" if e[idx]["data"].get("outcome") != "safe_output" else "unsafe_output"
        prev = e[idx]["prev"]
        for x in e[idx:]:
            x["prev"] = prev
            x["hash"] = entry_hash(x)
            prev = x["hash"]
    else:
        raise ValueError("unknown tamper mode")
    return e, cps, target


def tamper_test(entries, checkpoints, public_b64, mode):
    e, cps, target = tamper(entries, checkpoints, mode)
    res = verify(e, cps, public_b64, expect_sealed=mode not in ("truncate_unprotected",))
    return {"mode": mode, "description": TAMPER_MODES[mode], "target_seq": target,
            "detected": not res["ok"], "verification": res}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--audit", required=True)
    ap.add_argument("--checkpoints", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--sealed", action="store_true", help="require a checkpoint covering the final entry")
    a = ap.parse_args(argv)
    res = verify(read_jsonl(a.audit), read_jsonl(a.checkpoints), a.pubkey, expect_sealed=a.sealed)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
