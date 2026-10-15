"""Blue-team defence runner for the AegisLab prototype.

The defence runner is an isolated workload, not a blue-team participant. It
processes attack payloads during execution, but has no network and no channel
other than its broker mailbox, so blue-team people cannot see payloads before
the result gate releases them.

The defence configuration is mounted read-only from the run's frozen copy. On
start the runner hashes it and refuses to serve if the digest differs from the
one recorded in the frozen run manifest (passed in AEGIS_DEFENCE_DIGEST).
"""
import hashlib
import json
import os
import re
import sys

import spool

CONFIG_PATH = "/aegis/frozen/defence_config.json"


def load_config():
    raw = open(CONFIG_PATH, "rb").read()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    expected = os.environ.get("AEGIS_DEFENCE_DIGEST", "")
    if digest != expected:
        return None, digest
    cfg = json.loads(raw)
    cfg["_input"] = [re.compile(p, re.I) for p in cfg.get("input_patterns", [])]
    cfg["_output"] = [re.compile(p, re.I) for p in cfg.get("output_patterns", [])]
    return cfg, digest


CFG, DIGEST = load_config()


def inspect(text, patterns):
    for i, pat in enumerate(patterns):
        if pat.search(text):
            return {"ok": True, "verdict": "block", "rule": i}
    return {"ok": True, "verdict": "allow", "rule": None}


def handle(req):
    op = req.get("op")
    if op == "attest":
        return {"ok": CFG is not None, "config_digest": DIGEST}
    if CFG is None:
        return {"ok": False, "error": "config digest mismatch", "config_digest": DIGEST}
    text = str(req.get("text", ""))[:16000]
    if op == "inspect_input":
        return inspect(text, CFG["_input"])
    if op == "inspect_output":
        return inspect(text, CFG["_output"])
    return {"ok": False, "error": "unknown op"}


if __name__ == "__main__":
    spool.serve(handle)
    sys.exit(0)
