"""Hash-chained audit log with Ed25519-signed, chained checkpoints and a terminal anchor.

Each entry stores the hash of the previous entry, so editing, deleting or
reordering an entry breaks the chain. A hash chain alone cannot reveal
truncation of the tail or a wholesale rewrite by whoever holds the log, so the
control plane also signs checkpoints and pushes each one to an independent
reviewer vault.

Checkpoint format (v2). Every checkpoint is signed over:

    {v, run_id, seq, head, event_count, cp_seq, prev_cp, ts, reason, key_id, state}

* ``cp_seq`` is the 1-based index of the checkpoint and ``prev_cp`` the hash of
  the previous checkpoint's signed body, so the checkpoints form their own
  chain: removing, reordering or splicing in a checkpoint from elsewhere breaks it.
* A **terminal** checkpoint (``reason == "terminal"``) carries ``state``
  (``RELEASED`` or ``FAILED``), is written exactly once when the run reaches
  its legitimate end, and is the anchor a verifier requires. It is stored in
  the reviewer vault *and* in a separate anchor store outside the run directory.
* ``verify`` fails closed: with no terminal checkpoint a log is never reported
  valid unless the caller explicitly asks for an in-progress check
  (``require_terminal=False``), and that result is labelled ``terminal_verified: false``.

Legacy v1 checkpoints (``{run_id, seq, head, ts, reason, key_id}``) still verify
for chain consistency but cannot satisfy ``require_terminal``.
"""
import fcntl
import json
import threading
import time
from pathlib import Path

from .crypto import canonical, sha256, verify_signature

GENESIS = "sha256:" + "0" * 64
TERMINAL_STATES = ("RELEASED", "FAILED")
CP_VERSION = 2


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256(canonical(body))


def checkpoint_hash(cp: dict) -> str:
    """Hash of a checkpoint's signed body (the signature itself is not part of it)."""
    return sha256(canonical({k: v for k, v in cp.items() if k != "sig"}))


class AuditLog:
    """Append-only chained log. State is re-read from disk under a file lock on every write, so several
    ``Run`` objects in one process (broker thread, API handlers) cannot fork the chain."""

    def __init__(self, path: Path, run_id: str):
        self.path = Path(path)
        self.run_id = run_id
        self.lock = threading.Lock()

    def _tail(self) -> tuple:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        for line in self.path.read_text().splitlines():
            if line.strip():
                last = line
        if last is None:
            return 0, GENESIS
        e = json.loads(last)
        return e["seq"], e["hash"]

    @property
    def seq(self) -> int:
        return self._tail()[0]

    @property
    def head(self) -> str:
        return self._tail()[1]

    @property
    def closed_marker(self) -> Path:
        return self.path.with_name(self.path.name + ".closed")

    @property
    def closed(self) -> bool:
        return self.closed_marker.exists()

    def append(self, type_: str, actor: str, data: dict, close: bool = False):
        """Append one entry. With ``close=True`` the chain is closed in the same critical section (marker file
        written under the same file lock), so no other writer can add an entry between the final event and the
        terminal checkpoint. Returns None, writing nothing, if the chain is already closed."""
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                if self.closed:
                    return None
                seq, head = self._tail()
                entry = {"seq": seq + 1, "ts": round(time.time(), 6), "run_id": self.run_id,
                         "type": type_, "actor": actor, "data": data, "prev": head}
                entry["hash"] = entry_hash(entry)
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
                fh.flush()
                if close:
                    self.closed_marker.write_text(entry["hash"])
            return entry

    def checkpoint(self, signer, local_path: Path, vault_path: Path, reason: str, state: str = None,
                   extra_paths=()) -> dict:
        """Sign the current head. The previous checkpoint is read from the vault (independent copy).

        Once the chain is closed only the terminal checkpoint may still be written: a later non-terminal checkpoint
        would follow the terminal one and make a genuine run fail verification ("terminal checkpoint is not the last
        checkpoint"). Returns None in that case; the terminal checkpoint already covers every entry. A second terminal
        checkpoint is refused."""
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # The same file lock as append(): every API request builds its own AuditLog object, so the thread lock alone
            # does not stop two requests from signing a checkpoint with the same cp_seq at the same time.
            with self.path.open("a") as lockfh:
                fcntl.flock(lockfh, fcntl.LOCK_EX)
                if self.closed and reason != "terminal":
                    return None
                seq, head = self._tail()
                vault = read_jsonl(vault_path)
                if reason == "terminal" and any(c.get("reason") == "terminal" for c in vault):
                    raise ValueError("a terminal checkpoint already exists for this run")
                prev_cp = checkpoint_hash(vault[-1]) if vault else GENESIS
                body = {"v": CP_VERSION, "run_id": self.run_id, "seq": seq, "head": head,
                        "event_count": seq, "cp_seq": len(vault) + 1, "prev_cp": prev_cp,
                        "ts": round(time.time(), 6), "reason": reason, "key_id": signer.key_id}
                if state is not None:
                    body["state"] = state
                cp = dict(body, sig=signer.sign(body))
                line = json.dumps(cp, sort_keys=True) + "\n"
                for p in (Path(local_path), Path(vault_path), *map(Path, extra_paths)):
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with p.open("a") as fh:
                        fh.write(line)
                return cp


def read_jsonl(path: Path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _finding(findings, issue, **kw):
    findings.append(dict(kw, issue=issue))


def verify(entries, checkpoints, public_b64: str, expect_sealed: bool = False, *, require_terminal: bool = True,
           run_id: str = None, expected_state: str = None, expected_events: int = None, anchor: dict = None,
           expected_terminal_hash: str = None) -> dict:
    """Verify a log against independently held checkpoints. Fails closed.

    ``ok`` is True only if all of the following hold:
      * the entry chain is intact: contiguous seq starting at 1, prev links, hashes, one run_id;
      * every checkpoint signature verifies, belongs to this run, and matches the chain;
      * the checkpoints form an unbroken chain (cp_seq 1..n, prev_cp links, non-decreasing seq);
      * when ``require_terminal`` (the default): exactly one terminal checkpoint exists, it is the
        last checkpoint, its state is RELEASED or FAILED (and equals ``expected_state`` if given),
        and it binds the final entry: seq == event_count == len(entries) and head == final hash;
      * when given, ``expected_events`` equals the number of entries.

    ``anchor`` is a signed terminal checkpoint the reviewer retained separately (for example the
    ``terminal_anchor.json`` of the evidence bundle). When given it must verify, belong to this run and
    describe exactly the final entry; if the checkpoint list also holds a terminal checkpoint the two must be
    identical. A reviewer who kept only early checkpoints plus the anchor can therefore still detect truncation.

    ``expected_terminal_hash`` is the hash (``checkpoint_hash``) of the terminal checkpoint a reviewer wrote down when the
    run was released. Unlike the retained anchor it does not depend on any file the verified party can rewrite, so it
    still detects a complete re-signed history produced with a stolen key and replaced retained copies.

    ``expect_sealed`` is kept for compatibility and means "no entries after the last checkpoint".
    ``require_terminal=False`` is an explicit in-progress check; it is reported as ``terminal_verified: false``.
    """
    findings = []
    if (not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries)
            or not isinstance(checkpoints, list) or not all(isinstance(c, dict) and isinstance(c.get("seq"), int)
                                                            and not isinstance(c.get("seq"), bool) for c in checkpoints)):
        _finding(findings, "evidence is malformed: entries and checkpoints must be JSON objects and checkpoints need an integer seq")
        return {"ok": False, "entries": len(entries) if isinstance(entries, list) else 0, "chain_ok": False,
                "checkpoints_checked": len(checkpoints) if isinstance(checkpoints, list) else 0, "checkpoint_ok": False,
                "last_checkpoint_seq": 0, "tail_uncovered": 0, "terminal_required": require_terminal,
                "terminal_verified": False, "terminal_state": None, "anchor_checked": None, "terminal_hash": None,
                "findings": findings}
    heads = {}
    prev = GENESIS
    chain_ok = True
    rid = run_id
    for i, e in enumerate(entries):
        expected_seq = i + 1
        if e.get("seq") != expected_seq:
            _finding(findings, "sequence gap, duplicate or reorder (expected %d)" % expected_seq, seq=e.get("seq"))
            chain_ok = False
            break
        if rid is None:
            rid = e.get("run_id")
        if e.get("run_id") != rid:
            _finding(findings, "entry belongs to a different run", seq=e["seq"])
            chain_ok = False
            break
        if e.get("prev") != prev:
            _finding(findings, "prev hash does not match preceding entry", seq=e["seq"])
            chain_ok = False
            break
        if entry_hash(e) != e.get("hash"):
            _finding(findings, "entry content does not match its hash", seq=e["seq"])
            chain_ok = False
            break
        prev = e["hash"]
        heads[e["seq"]] = e["hash"]

    cp_ok = True
    last_cp_seq = 0
    prev_cp, prev_cp_seq, prev_entry_seq = GENESIS, 0, 0
    terminals = []
    legacy = False
    for idx, cp in enumerate(checkpoints):
        body = {k: v for k, v in cp.items() if k != "sig"}
        if not verify_signature(public_b64, body, cp.get("sig", "")):
            _finding(findings, "checkpoint signature invalid", checkpoint_seq=cp.get("seq"))
            cp_ok = False
            continue
        if rid is not None and cp.get("run_id") != rid:
            _finding(findings, "checkpoint belongs to a different run", checkpoint_seq=cp.get("seq"))
            cp_ok = False
            continue
        last_cp_seq = max(last_cp_seq, cp["seq"])
        if cp.get("v") == CP_VERSION:
            if cp.get("cp_seq") != idx + 1:
                _finding(findings, "checkpoint index gap or reorder (expected cp_seq %d, got %s)"
                         % (idx + 1, cp.get("cp_seq")), checkpoint_seq=cp.get("seq"))
                cp_ok = False
            if cp.get("prev_cp") != prev_cp:
                _finding(findings, "checkpoint chain broken (prev_cp mismatch)", checkpoint_seq=cp.get("seq"))
                cp_ok = False
            if cp["seq"] < prev_entry_seq:
                _finding(findings, "checkpoint seq goes backwards", checkpoint_seq=cp.get("seq"))
                cp_ok = False
            if cp.get("event_count") != cp["seq"]:
                _finding(findings, "checkpoint event_count differs from its seq", checkpoint_seq=cp.get("seq"))
                cp_ok = False
            prev_cp, prev_cp_seq, prev_entry_seq = checkpoint_hash(cp), idx + 1, cp["seq"]
            if cp.get("reason") == "terminal":
                terminals.append((idx, cp))
        else:
            legacy = True
        if cp["seq"] > len(entries):
            _finding(findings, "log has %d entries but a signed checkpoint covers seq %d: truncation"
                     % (len(entries), cp["seq"]), checkpoint_seq=cp["seq"])
            cp_ok = False
        elif chain_ok and heads.get(cp["seq"]) != cp["head"]:
            _finding(findings, "chain head differs from signed checkpoint", checkpoint_seq=cp["seq"])
            cp_ok = False

    terminal_ok, terminal_state, terminal_hash = False, None, None
    anchor_ok = None
    anchor_cp = None
    if anchor is not None:
        abody = {k: v for k, v in anchor.items() if k != "sig"}
        if not verify_signature(public_b64, abody, anchor.get("sig", "")):
            _finding(findings, "retained terminal anchor: signature invalid")
        elif rid is not None and anchor.get("run_id") != rid:
            _finding(findings, "retained terminal anchor belongs to a different run")
        elif anchor.get("v") != CP_VERSION or anchor.get("reason") != "terminal":
            _finding(findings, "retained terminal anchor is not a v%d terminal checkpoint" % CP_VERSION)
        else:
            anchor_cp = anchor
        anchor_ok = anchor_cp is not None
    if require_terminal:
        in_list = terminals[0][1] if len(terminals) == 1 else None
        if not terminals and anchor_cp is None:
            _finding(findings, "no signed terminal checkpoint: completeness of the log cannot be established"
                               "%s" % (" (legacy checkpoints only)" if legacy else ""))
        elif len(terminals) > 1:
            _finding(findings, "more than one terminal checkpoint")
        else:
            t = in_list or anchor_cp
            problems = []
            if in_list is not None and terminals[0][0] != len(checkpoints) - 1:
                problems.append("terminal checkpoint is not the last checkpoint")
            if in_list is not None and anchor_cp is not None and checkpoint_hash(in_list) != checkpoint_hash(anchor_cp):
                problems.append("retained anchor differs from the terminal checkpoint in the vault")
            if anchor is not None and anchor_cp is None:
                problems.append("a terminal anchor was supplied but is not valid")
            terminal_state = t.get("state")
            terminal_hash = checkpoint_hash(t)
            if expected_terminal_hash is not None and terminal_hash != expected_terminal_hash:
                problems.append("terminal checkpoint hash differs from the one the reviewer recorded at release")
            if terminal_state not in TERMINAL_STATES:
                problems.append("terminal state %r is not one of %s" % (terminal_state, "/".join(TERMINAL_STATES)))
            if expected_state is not None and terminal_state != expected_state:
                problems.append("terminal state %r differs from the run's recorded state %r"
                                % (terminal_state, expected_state))
            if t.get("seq") != len(entries) or t.get("event_count") != len(entries):
                problems.append("log has %d entries but the terminal checkpoint binds %s: %s"
                                % (len(entries), t.get("event_count"),
                                   "truncation" if len(entries) < (t.get("event_count") or 0) else "extra entries"))
            elif chain_ok and entries and t.get("head") != entries[-1]["hash"]:
                problems.append("terminal head differs from the final entry hash")
            if entries and entries[-1].get("type") not in ("run.released", "run.failed"):
                problems.append("final entry %r is not a terminal lifecycle event" % entries[-1].get("type"))
            if (entries and t.get("state") == "RELEASED" and entries[-1].get("type") != "run.released") or \
               (entries and t.get("state") == "FAILED" and entries[-1].get("type") != "run.failed"):
                problems.append("terminal state %s does not match the final lifecycle event" % t.get("state"))
            for p in problems:
                _finding(findings, p, checkpoint_seq=t.get("seq"))
            terminal_ok = not problems
    if expected_events is not None and expected_events != len(entries):
        _finding(findings, "expected %d entries, log has %d" % (expected_events, len(entries)))

    if terminal_ok:  # a verified terminal checkpoint or anchor covers the final entry
        last_cp_seq = max(last_cp_seq, len(entries))
    tail_uncovered = max(0, len(entries) - last_cp_seq)
    if expect_sealed and tail_uncovered:
        _finding(findings, "%d entries after the last independently held checkpoint" % tail_uncovered)
    events_ok = expected_events is None or expected_events == len(entries)
    ok = (chain_ok and cp_ok and bool(checkpoints) and not (expect_sealed and tail_uncovered)
          and (terminal_ok or not require_terminal) and events_ok)
    return {"ok": ok, "entries": len(entries), "chain_ok": chain_ok, "checkpoints_checked": len(checkpoints),
            "checkpoint_ok": cp_ok, "last_checkpoint_seq": last_cp_seq, "tail_uncovered": tail_uncovered,
            "terminal_required": require_terminal, "terminal_verified": bool(terminal_ok),
            "terminal_state": terminal_state, "anchor_checked": anchor_ok, "terminal_hash": terminal_hash,
            "findings": findings}
