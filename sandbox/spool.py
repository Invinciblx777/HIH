"""Mailbox (spool) IPC used inside AegisLab sandboxes.

Tenant containers run with ``--network none``. The only channel to the trusted
broker is a private bind-mounted directory with two subdirectories:

    /aegis/spool/out   messages written by this container
    /aegis/spool/in    messages written by the broker

Messages are single JSON files written atomically (temp file + rename).
Standard library only, so the sandbox image needs no extra packages.
"""
import json
import os
import time

SPOOL = os.environ.get("AEGIS_SPOOL", "/aegis/spool")
OUT = os.path.join(SPOOL, "out")
IN = os.path.join(SPOOL, "in")
POLL_S = 0.003


def _write(directory, name, obj):
    tmp = os.path.join(directory, "." + name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, separators=(",", ":"))
    os.rename(tmp, os.path.join(directory, name))


def _wait(directory, name, timeout_s):
    path = os.path.join(directory, name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            os.unlink(path)
            return data
        time.sleep(POLL_S)
    raise TimeoutError(name)


class Client:
    """Request/response client used by the red sandbox."""

    def __init__(self):
        self.seq = 0

    def call(self, msg, timeout_s=30.0):
        self.seq += 1
        name = "%06d.json" % self.seq
        msg = dict(msg, seq=self.seq)
        _write(OUT, name, msg)
        return _wait(IN, name, timeout_s)


def serve(handler, idle_timeout_s=600.0):
    """Server loop used by the defence runner and model worker.

    The broker writes requests into ``in``; replies go to ``out`` with the same
    file name. A message with op == "shutdown" ends the loop.
    """
    last = time.monotonic()
    while time.monotonic() - last < idle_timeout_s:
        names = sorted(n for n in os.listdir(IN) if n.endswith(".json"))
        if not names:
            time.sleep(POLL_S)
            continue
        for name in names:
            path = os.path.join(IN, name)
            with open(path, encoding="utf-8") as fh:
                req = json.load(fh)
            os.unlink(path)
            if req.get("op") == "shutdown":
                _write(OUT, name, {"ok": True})
                return
            try:
                resp = handler(req)
            except Exception as exc:  # report, never crash silently
                resp = {"ok": False, "error": type(exc).__name__}
            _write(OUT, name, resp)
            last = time.monotonic()
