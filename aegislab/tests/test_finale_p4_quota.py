"""Finale P4, SHOULD 8: per-tenant mailbox quotas (message count, rate, bytes, files present). Over any quota the broker stops
serving the tenant, records mailbox.quota_exceeded once, and seals the run as incomplete. The real Broker.execute loop reads
a real outbox directory; only the containers are absent.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.setattr(runtime, "running", lambda name: False)
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def test_P4Q01_each_quota_trips_just_above_its_limit():
    q = runs.MailboxQuota()
    assert q.on_listing(q.FILES) is None and q.on_listing(q.FILES + 1)["quota"] == "files"
    clk = Clock()
    q = runs.MailboxQuota(clock=clk)
    for i in range(q.RATE_N):
        assert q.on_message(10) is None
    assert q.on_message(10)["quota"] == "rate"
    clk = Clock()
    q = runs.MailboxQuota(clock=clk)
    for i in range(q.MESSAGES):
        clk.t += 1.0  # slow enough for the rate quota
        assert q.on_message(10) is None, i
    clk.t += 1.0
    assert q.on_message(10)["quota"] == "messages"
    q = runs.MailboxQuota(clock=Clock())
    assert q.on_message(q.BYTES) is None and q.on_message(1)["quota"] == "bytes"


def test_P4Q02_the_scripted_red_agent_stays_far_below_every_quota():
    q = runs.MailboxQuota()
    assert q.MESSAGES >= 4 * runs.MAX_COMMITMENTS and q.RATE_N >= 100 and q.BYTES >= 500 * runs.MAX_MSG and q.FILES >= 256


class Outbox(runs.Broker):
    """execute() with the red outbox pre-filled by the test instead of a red container."""

    def __init__(self, run, messages, extra_files=0):
        super().__init__(run)
        self._mk_spool("red")
        self.names = {"red": "no-such-container"}
        self.messages, self.extra = messages, extra_files

    def start_workloads(self):
        out = self.spool["red"] / "out"
        for i, m in enumerate(self.messages):
            (out / ("%06d.json" % (i + 1))).write_text(json.dumps(m))
        for i in range(self.extra):
            (out / ("junk-%d" % i)).write_text("x")

    def stop_workloads(self):
        pass

    def call(self, role, msg, timeout=15.0):
        if role == "blue":
            return {"ok": True, "verdict": "allow", "rule": None}
        return {"ok": True, "text": "fine"}


def run_outbox(rid, messages, extra_files=0):
    runs.create_run(rid, timing_bucket_ms=0)
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    b = Outbox(run, messages, extra_files)
    b.execute()
    return runs.Run(rid), read_jsonl(run.dir / "audit.jsonl")


def test_P4Q10_a_message_flood_is_cut_off_and_the_run_sealed_incomplete(monkeypatch):
    monkeypatch.setattr(runs.MailboxQuota, "MESSAGES", 20)
    run, audit = run_outbox("T-Q10", [{"op": "get_verdicts"}] * 40)
    q = [e for e in audit if e["type"] == "mailbox.quota_exceeded"]
    assert len(q) == 1 and q[0]["data"] == {"tenant": "red", "quota": "messages", "limit": 20, "observed": 21}
    assert run.state == "SEALED" and run.record["complete"] is False
    sealed = [e for e in audit if e["type"] == "run.sealed"][0]["data"]
    assert sealed["aborted"] == "red mailbox quota exceeded" and sealed["complete"] is False
    assert len([e for e in audit if e["type"] == "policy.denied"]) == 20  # message 21 was never processed


def test_P4Q11_too_many_files_in_the_outbox(monkeypatch):
    monkeypatch.setattr(runs.MailboxQuota, "FILES", 8)
    run, audit = run_outbox("T-Q11", [{"op": "done", "observed": []}], extra_files=10)
    q = [e["data"] for e in audit if e["type"] == "mailbox.quota_exceeded"]
    assert q == [{"tenant": "red", "quota": "files", "limit": 8, "observed": 11}] and run.record["complete"] is False


def test_P4Q12_byte_quota(monkeypatch):
    monkeypatch.setattr(runs.MailboxQuota, "BYTES", 2000)
    big = {"op": "get_verdicts", "pad": "x" * 900}
    run, audit = run_outbox("T-Q12", [big] * 5)
    q = [e["data"] for e in audit if e["type"] == "mailbox.quota_exceeded"]
    assert len(q) == 1 and q[0]["quota"] == "bytes" and q[0]["observed"] > 2000


def test_P4Q13_a_normal_run_is_unaffected():
    msgs = [{"op": "commit", "commitments": [{"attack_id": "A1", "digest": commitment("n1", "hello")}]},
            {"op": "attack", "attack_id": "A1", "payload": "hello", "nonce": "n1"}, {"op": "done", "observed": []}]
    run, audit = run_outbox("T-Q13", msgs)
    assert not [e for e in audit if e["type"] == "mailbox.quota_exceeded"]
    assert run.state == "SEALED" and run.record["complete"] is True
