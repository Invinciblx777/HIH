"""Hash-chained audit log with Ed25519-signed checkpoints.

Each entry stores the hash of the previous entry, so editing, deleting or
reordering an entry breaks the chain. A hash chain alone cannot reveal
truncation of the tail or a wholesale rewrite by whoever holds the log, so the
control plane also signs checkpoints {run_id, seq, head} and pushes each one to
an independent reviewer vault. Verification compares the log against the
checkpoints the reviewer kept, not the ones stored next to the log.
"""
import json
import threading
import time
from pathlib import Path

from .crypto import canonical, sha256, verify_signature

GENESIS = "sha256:" + "0" * 64


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256(canonical(body))


class AuditLog:
    def __init__(self, path: Path, run_id: str):
        self.path = Path(path)
        self.run_id = run_id
        self.lock = threading.Lock()
        self.seq, self.head = 0, GENESIS
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                e = json.loads(line)
                self.seq, self.head = e["seq"], e["hash"]

    def append(self, type_: str, actor: str, data: dict) -> dict:
        with self.lock:
            entry = {"seq": self.seq + 1, "ts": round(time.time(), 6), "run_id": self.run_id,
                     "type": type_, "actor": actor, "data": data, "prev": self.head}
            entry["hash"] = entry_hash(entry)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            self.seq, self.head = entry["seq"], entry["hash"]
            return entry

    def checkpoint(self, signer, local_path: Path, vault_path: Path, reason: str) -> dict:
        with self.lock:
            body = {"run_id": self.run_id, "seq": self.seq, "head": self.head,
                    "ts": round(time.time(), 6), "reason": reason, "key_id": signer.key_id}
            cp = dict(body, sig=signer.sign(body))
            line = json.dumps(cp, sort_keys=True) + "\n"
            for p in (Path(local_path), Path(vault_path)):
                p.parent.mkdir(parents=True, exist_ok=True)
                with p.open("a") as fh:
                    fh.write(line)
            return cp


def read_jsonl(path: Path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def verify(entries, checkpoints, public_b64: str, expect_sealed: bool = False) -> dict:
    """Verify a log against independently held checkpoints.

    Returns a structured result; ``ok`` is True only if the chain is intact,
    every checkpoint signature verifies and matches the chain, and (when
    ``expect_sealed``) a checkpoint covers the final entry.
    """
    findings = []
    heads = {}
    prev = GENESIS
    chain_ok = True
    for i, e in enumerate(entries):
        expected_seq = i + 1
        if e.get("seq") != expected_seq:
            findings.append({"seq": e.get("seq"), "issue": "sequence gap or reorder (expected %d)" % expected_seq})
            chain_ok = False
            break
        if e.get("prev") != prev:
            findings.append({"seq": e["seq"], "issue": "prev hash does not match preceding entry"})
            chain_ok = False
            break
        if entry_hash(e) != e.get("hash"):
            findings.append({"seq": e["seq"], "issue": "entry content does not match its hash"})
            chain_ok = False
            break
        prev = e["hash"]
        heads[e["seq"]] = e["hash"]

    cp_ok = True
    last_cp_seq = 0
    for cp in checkpoints:
        body = {k: v for k, v in cp.items() if k != "sig"}
        if not verify_signature(public_b64, body, cp.get("sig", "")):
            findings.append({"checkpoint_seq": cp.get("seq"), "issue": "checkpoint signature invalid"})
            cp_ok = False
            continue
        last_cp_seq = max(last_cp_seq, cp["seq"])
        if cp["seq"] > len(entries):
            findings.append({"checkpoint_seq": cp["seq"],
                             "issue": "log has %d entries but a signed checkpoint covers seq %d: truncation"
                                      % (len(entries), cp["seq"])})
            cp_ok = False
        elif chain_ok and heads.get(cp["seq"]) != cp["head"]:
            findings.append({"checkpoint_seq": cp["seq"], "issue": "chain head differs from signed checkpoint"})
            cp_ok = False

    tail_uncovered = max(0, len(entries) - last_cp_seq)
    if expect_sealed and tail_uncovered:
        findings.append({"issue": "%d entries after the last independently held checkpoint" % tail_uncovered})
    ok = chain_ok and cp_ok and bool(checkpoints) and not (expect_sealed and tail_uncovered)
    return {"ok": ok, "entries": len(entries), "chain_ok": chain_ok, "checkpoints_checked": len(checkpoints),
            "checkpoint_ok": cp_ok, "last_checkpoint_seq": last_cp_seq, "tail_uncovered": tail_uncovered,
            "findings": findings}
