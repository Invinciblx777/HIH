"""Finale P4, SHOULD 7: the reviewer's countersignature on a released run's terminal checkpoint.

Before P4 everything the verifier checks was signed by one key, the broker's. Whoever stole that key and could replace every
retained copy produced a history that verified as consistent (the documented limit in scripts/security_demo.py step 7); only
a terminal hash written down out of band (verify_cli --expect-terminal-hash) caught it. The countersignature is that record
in signed form, by a second party with a second key:

    {"v": 1, "kind": "aegis-reviewer-countersignature", "run_id", "state", "terminal_hash", "event_count", "head",
     "broker_key_id", "reviewer_key_id", "ts", "sig"}

signed with the reviewer key (Ed25519). It binds the terminal checkpoint by its hash, so a re-signed history, even one with a
valid broker signature, does not match it. verify_cli --require-countersignature --reviewer-pubkey KEY then requires BOTH:
the broker's checkpoints and the reviewer's countersignature, under a pinned reviewer key.

Where the reviewer key lives. A countersignature adds a second party only when the reviewer key is out of the broker host's
reach. Two ways are supported:
  * offline (the intended deployment): the reviewer verifies the exported bundle on their own machine with the pinned broker
    key and countersigns it there:  python -m aegis.countersign --bundle DIR --key reviewer_ed25519.pem
    (writes DIR/reviewer_countersignature.json and DIR/reviewer_public_key.b64);
  * on release (the prototype's convenience): when the reviewer releases through the API, the control plane countersigns with
    var/keys/reviewer_ed25519.pem (or AEGIS_REVIEWER_KEY). That key is separate from the evidence and capability keys but on the
    same host: against an attacker who holds the host it adds nothing (THREAT_MODEL.md section 10.7, label Partial).
"""
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

from . import store
from .audit import checkpoint_hash, read_jsonl, verify
from .crypto import Signer, sha256, verify_signature

KIND = "aegis-reviewer-countersignature"
FIELDS = ("run_id", "state", "terminal_hash", "event_count", "head", "broker_key_id")


def reviewer_key_path() -> Path:
    return Path(os.environ.get("AEGIS_REVIEWER_KEY") or store.p("keys", "reviewer_ed25519.pem"))


def countersignature_path(run_id: str) -> Path:
    """Next to the terminal anchor (the anchor store), outside the run directory."""
    return store.anchor_path(run_id).with_name(run_id + ".reviewer.json")


def make(anchor: dict, entries: list, signer: Signer, now=None) -> dict:
    """Countersign a terminal checkpoint ``anchor`` that has ALREADY been verified against ``entries``."""
    body = {"v": 1, "kind": KIND, "run_id": anchor["run_id"], "state": anchor["state"], "terminal_hash": checkpoint_hash(anchor),
            "event_count": len(entries), "head": entries[-1]["hash"], "broker_key_id": anchor.get("key_id"),
            "reviewer_key_id": signer.key_id, "ts": time.time() if now is None else now}
    return dict(body, sig=signer.sign(body))


def check(cs, reviewer_pub_b64: str, result: dict, run_id=None) -> list:
    """Findings (empty = valid) for countersignature ``cs`` against a verify() ``result`` of the same evidence."""
    if not isinstance(cs, dict):
        return ["reviewer countersignature missing"]
    body = {k: v for k, v in cs.items() if k != "sig"}
    out = []
    try:
        kid = sha256(base64.b64decode(reviewer_pub_b64, validate=True))[:23]
    except ValueError:
        return ["reviewer public key is not valid base64"]
    if body.get("kind") != KIND or body.get("v") != 1:
        out.append("not a reviewer countersignature")
    if not verify_signature(reviewer_pub_b64, body, cs.get("sig", "")):
        out.append("reviewer countersignature does not verify under the reviewer key")
    if body.get("reviewer_key_id") != kid:
        out.append("countersignature names a different reviewer key")
    if run_id is not None and body.get("run_id") != run_id:
        out.append("countersignature is for another run")
    if not result.get("terminal_verified") or body.get("terminal_hash") != result.get("terminal_hash"):
        out.append("countersignature does not match the terminal checkpoint (re-signed or different history)")
    if body.get("state") != result.get("terminal_state"):
        out.append("countersignature state differs from the terminal state")
    if body.get("event_count") != result.get("entries"):
        out.append("countersignature event count differs from the log")
    return out


def countersign_on_release(run_id: str, anchor: dict, entries: list) -> dict:
    cs = make(anchor, entries, Signer(reviewer_key_path()))
    path = countersignature_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        os.chmod(path, 0o644)
    path.write_text(json.dumps(cs, sort_keys=True, indent=2) + "\n")
    os.chmod(path, 0o444)
    return cs


def main(argv=None):
    ap = argparse.ArgumentParser(description="Countersign a verified evidence bundle with the reviewer key (offline)")
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--key", required=True, help="the reviewer's Ed25519 private key (PEM, created if missing)")
    ap.add_argument("--broker-pubkey", help="pinned broker key (base64); default: the bundle's, with a warning")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--expect-state", required=True, choices=["RELEASED", "FAILED"])
    a = ap.parse_args(argv)
    d = Path(a.bundle)
    pub = (a.broker_pubkey or (d / "broker_public_key.b64").read_text()).strip()
    entries, cps = read_jsonl(d / "audit.jsonl"), read_jsonl(d / "reviewer_checkpoints.jsonl")
    anchor = json.loads((d / "terminal_anchor.json").read_text())
    res = verify(entries, cps, pub, expect_sealed=True, run_id=a.run_id, expected_state=a.expect_state, anchor=anchor)
    if not res["ok"] or not res["terminal_verified"]:
        print(json.dumps({"ok": False, "reason": "bundle does not verify; refusing to countersign", "findings": res["findings"]}, indent=2))
        return 1
    s = Signer(Path(a.key))
    cs = make(anchor, entries, s)
    (d / "reviewer_countersignature.json").write_text(json.dumps(cs, sort_keys=True, indent=2) + "\n")
    (d / "reviewer_public_key.b64").write_text(s.public_b64() + "\n")
    print(json.dumps({"ok": True, "terminal_hash": cs["terminal_hash"], "reviewer_key_id": s.key_id,
                      "broker_key": "pinned" if a.broker_pubkey else "from the bundle (NOT pinned)"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
