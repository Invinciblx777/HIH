"""Red-team sandbox agent for the AegisLab prototype.

Runs inside a container with no network. It reads the red team's private attack
pack, commits to every payload (SHA-256 over a random nonce and the payload),
then submits attacks one at a time through the broker. It also performs a set
of deliberately forbidden actions so the run records how the boundary answers.
"""
import hashlib
import json
import os
import socket
import time

import spool

PACK_PATH = "/aegis/private/attack_pack.json"


def commitment(nonce, payload):
    return "sha256:" + hashlib.sha256((nonce + "\x00" + payload).encode()).hexdigest()


def self_checks():
    """Observations made from inside the sandbox; reported to the broker."""
    checks = []
    for host, port in (("1.1.1.1", 53), ("10.0.2.2", 8400), ("127.0.0.1", 8400)):
        try:
            socket.create_connection((host, port), timeout=1).close()
            checks.append({"check": "tcp %s:%d" % (host, port), "result": "connected"})
        except OSError as exc:
            checks.append({"check": "tcp %s:%d" % (host, port), "result": "failed", "errno": exc.errno})
    for path in ("/aegis/frozen", "/aegis/blue", "/run/aegis", "/aegis/sealed", "/aegis/spool/blue",
                 "/aegis/spool/model", "/aegis/state", "/var/lib/aegis"):
        checks.append({"check": "path " + path, "result": "visible" if os.path.exists(path) else "absent"})
    try:
        open("/usr/aegis-write-test", "w").close()
        checks.append({"check": "write rootfs", "result": "writable"})
    except OSError as exc:
        checks.append({"check": "write rootfs", "result": "denied", "errno": exc.errno})
    try:
        open("/aegis/private/attack_pack.tamper", "w").close()
        checks.append({"check": "write /aegis/private", "result": "writable"})
    except OSError as exc:
        checks.append({"check": "write /aegis/private", "result": "denied", "errno": exc.errno})
    checks.append({"check": "uid", "result": str(os.getuid())})
    try:
        for line in open("/proc/self/status"):
            key = line.split(":")[0]
            if key in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp"):
                checks.append({"check": "proc " + key, "result": line.split(":", 1)[1].strip()})
    except OSError:
        pass
    return checks


def main():
    pack = json.load(open(PACK_PATH, encoding="utf-8"))
    client = spool.Client()
    client.call({"op": "selfcheck", "checks": self_checks()})

    attacks = []
    for item in pack["attacks"]:
        nonce = os.urandom(16).hex()
        attacks.append(dict(item, nonce=nonce, digest=commitment(nonce, item["payload"])))
    client.call({"op": "commit", "commitments": [{"attack_id": a["id"], "digest": a["digest"]} for a in attacks]})

    if pack.get("forbidden_probes", True):
        client.call({"op": "read_artifact", "target": "blue/defence_config"})
        client.call({"op": "get_verdicts"})
        client.call({"op": "release_results"})
        client.call({"op": "attack", "attack_id": "X-UNCOMMITTED", "payload": "not committed", "nonce": "00"})
        client.call({"op": "attack", "tenant": "blue", "attack_id": "X-SPOOF", "payload": "spoofed", "nonce": "00"})

    observed = []
    for a in attacks:
        t0 = time.perf_counter()
        resp = client.call({"op": "attack", "attack_id": a["id"], "payload": a["payload"], "nonce": a["nonce"]})
        observed.append({"attack_id": a["id"], "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
                         "refused": resp.get("refused")})
    client.call({"op": "done", "observed": observed})


if __name__ == "__main__":
    main()
