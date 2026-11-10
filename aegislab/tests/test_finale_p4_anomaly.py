"""Finale P4, task 4: anomaly detectors. Each fires at its stated threshold and not below; alerts are in the audit chain;
the operator and reviewer see them live and everyone else only after SEALED; and detection opens no content or timing
channel to red (red's replies, their bytes and their release times are the same whether or not a detector fired).

Real Broker.dispatch / deny / attack / seal; the defence runner and the model are in-process fakes (as in
test_finale_p4_release_timing.py).
"""
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import anomaly, runs, runtime, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.crypto import commitment  # noqa: E402

TOL_MS = 20


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# ---------------------------------------------------------------- thresholds (unit)
def test_P4A01_every_detector_states_a_threshold_and_a_rationale():
    assert set(anomaly.DETECTORS) == {"denial_burst", "forbidden_sweep", "mailbox_violations", "canary_near_miss",
                                      "model_cutoffs", "latency_drift"}
    for name, d in anomaly.DETECTORS.items():
        assert d["threshold"] and len(d["rationale"]) > 60, name


def test_P4A02_denial_burst_fires_at_five_within_ten_seconds_and_not_at_four():
    clk = Clock()
    d = anomaly.Detectors(clock=clk)
    for _ in range(4):
        d.observe_denial("attack")
        clk.t += 2.0
    assert not [a for a in d.pending if a["detector"] == "denial_burst"]
    clk.t += 3.0  # now 1011: the first denial (1000) leaves the 10 s window, still four
    d.observe_denial("attack")
    assert not [a for a in d.pending if a["detector"] == "denial_burst"]
    d.observe_denial("attack")
    assert [a["detector"] for a in d.drain()] == ["denial_burst"]


def test_P4A03_forbidden_sweep_needs_three_distinct_operations():
    d = anomaly.Detectors()
    for _ in range(4):
        d.observe_denial("read_artifact")
    d.observe_denial("get_verdicts")
    assert not [a for a in d.pending if a["detector"] == "forbidden_sweep"]
    d.observe_denial("release_results")
    sweep = [a for a in d.drain() if a["detector"] == "forbidden_sweep"]
    assert len(sweep) == 1 and sweep[0]["observed"]["distinct_ops"] == ["get_verdicts", "read_artifact", "release_results"]


def test_P4A04_mailbox_violations_two_within_sixty_seconds():
    clk = Clock()
    d = anomaly.Detectors(clock=clk)
    d.observe_mailbox_violation()
    clk.t += 61
    d.observe_mailbox_violation()
    assert not d.pending
    clk.t += 30
    d.observe_mailbox_violation()
    assert [a["detector"] for a in d.drain()] == ["mailbox_violations"]


def test_P4A05_near_miss_three_attacks_on_one_canary_or_one_base64_fragment():
    d = anomaly.Detectors()
    d.observe_attack("safe_output", 5, 1, {"CANARY-aaaaaaaaaaaa": 7})
    d.observe_attack("safe_output", 5, 1, {"CANARY-bbbbbbbbbbbb": 6})
    d.observe_attack("safe_output", 5, 1, {"CANARY-aaaaaaaaaaaa": 6})
    assert not [a for a in d.pending if a["detector"] == "canary_near_miss"]
    d.observe_attack("safe_output", 5, 1, {"CANARY-aaaaaaaaaaaa": 8})
    hit = [a for a in d.drain() if a["detector"] == "canary_near_miss"]
    assert len(hit) == 1 and hit[0]["observed"]["max_attacks_one_canary"] == 3
    assert "CANARY-aaaaaaaaaaaa" not in json.dumps(hit)  # another run's canary is never written into this run's record
    d2 = anomaly.Detectors()
    d2.observe_attack("safe_output", 5, 1, {"CANARY-cccccccccccc": 12})
    assert [a["observed"]["base64_fragment"] for a in d2.drain() if a["detector"] == "canary_near_miss"] == [True]


def test_P4A06_model_cutoffs_three_of_the_last_ten():
    d = anomaly.Detectors()
    for o in ["cut_off", "safe_output", "model_error"] + ["safe_output"] * 9 + ["cut_off"]:
        d.observe_attack(o, 5, 1)
    assert not [a for a in d.pending if a["detector"] == "model_cutoffs"]  # the first two have left the window of ten
    d.observe_attack("cut_off", 5, 1)
    d.observe_attack("model_error", 5, 1)
    assert [a["detector"] for a in d.drain()] == ["model_cutoffs"]


def test_P4A07_latency_drift_against_the_first_ten():
    d = anomaly.Detectors()
    for _ in range(10):
        d.observe_attack("safe_output", 200, 190)  # overhead 10 ms
    for _ in range(10):
        d.observe_attack("safe_output", 1265, 1200)  # overhead 65 ms: > 10 + 50 ms; the model time is not counted
    assert [a["detector"] for a in d.drain()] == ["latency_drift"]
    d2 = anomaly.Detectors()
    for _ in range(10):
        d2.observe_attack("safe_output", 200, 190)
    for _ in range(10):
        d2.observe_attack("safe_output", 2000, 1955)  # overhead 45 ms: below both bounds
    assert not d2.pending


def test_P4A08_an_alert_fires_on_the_rising_edge_once_per_episode():
    clk = Clock()
    d = anomaly.Detectors(clock=clk)
    for _ in range(9):
        d.observe_denial("attack")
    assert [a["detector"] for a in d.drain()] == ["denial_burst"]
    clk.t += 30
    for _ in range(5):
        d.observe_denial("attack")
    assert [(a["detector"], a["occurrence"]) for a in d.drain()] == [("denial_burst", 2)]


# ---------------------------------------------------------------- the broker
@pytest.fixture(autouse=True)
def isolated_var(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    monkeypatch.setattr(runtime, "image_id", lambda *a: "0" * 64)
    monkeypatch.setattr(runtime, "image_repo_digest", lambda *a: "sha256:t")
    monkeypatch.setattr(runtime, "environment", lambda: {})
    monkeypatch.delenv("AEGIS_VAULT", raising=False)
    monkeypatch.delenv("AEGIS_ANCHORS", raising=False)


class Bench(runs.Broker):
    def __init__(self, run, model_s=0.01, answer=lambda p: "echo: " + p[:20]):
        super().__init__(run)
        self._mk_spool("red")
        self.names = {"red": "no-such-container"}
        self.model_s, self.answer, self.events = model_s, answer, []

    def call(self, role, msg, timeout=15.0):
        if role == "blue":
            return {"ok": True, "verdict": "block" if msg["text"].startswith("BLOCK") else "allow", "rule": None}
        if self.model_s > timeout:
            time.sleep(timeout)
            raise TimeoutError("model did not answer")
        time.sleep(self.model_s)
        return {"ok": True, "text": self.answer(msg["prompt"])}

    def reply_red(self, name, obj):
        self.events.append(("reply", time.monotonic(), name, json.dumps(obj, sort_keys=True)))
        super().reply_red(name, obj)

    def start_workloads(self):
        pass

    def stop_workloads(self):
        pass


def bench(run_id, deadline=None, bucket=0, **kw):
    runs.create_run(run_id, timing_bucket_ms=bucket, timing_deadline_ms=deadline)
    runs.freeze(run_id)
    run = runs.Run(run_id)
    run.update(state="RUNNING")
    return Bench(run, **kw)


PROBES = [{"op": "read_artifact", "target": "blue/defence_config"}, {"op": "get_verdicts"}, {"op": "release_results"},
          {"op": "attack", "attack_id": "X-UNCOMMITTED", "payload": "not committed", "nonce": "00"},
          {"op": "attack", "tenant": "blue", "attack_id": "X-SPOOF", "payload": "spoofed", "nonce": "00"}]


def play(b, attacks, probes=True):
    """The scripted red agent's order: commit, forbidden probes, attacks. Returns [(name, latency ms, reply bytes)]."""
    n = 1
    b.dispatch("%06d.json" % n, {"op": "commit", "commitments": [{"attack_id": a, "digest": commitment("n" + a, p)} for a, p in attacks]})
    out = []
    for m in (PROBES if probes else []):
        n += 1
        t = time.monotonic()
        b.dispatch("%06d.json" % n, dict(m))
        r = b.events[-1]
        out.append((r[2], (r[1] - t) * 1000, r[3]))
    for a, p in attacks:
        n += 1
        t = time.monotonic()
        b.dispatch("%06d.json" % n, {"op": "attack", "attack_id": a, "payload": p, "nonce": "n" + a})
        r = b.events[-1]
        out.append((r[2], (r[1] - t) * 1000, r[3]))
    return out


ATTACKS = [("A%02d" % i, ("BLOCK " if i % 2 else "") + "payload %d" % i) for i in range(1, 7)]


def audit(b):
    return read_jsonl(b.run.dir / "audit.jsonl")


def test_P4A10_the_scripted_probes_fire_burst_and_sweep_written_before_the_first_attacks_release():
    b = bench("T-P4A10", deadline=300)
    real_log = runs.Run.log
    order = []

    def spy(self, type_, *a, **kw):
        order.append((type_, time.monotonic()))
        return real_log(self, type_, *a, **kw)
    runs.Run.log = spy
    try:
        play(b, ATTACKS)
    finally:
        runs.Run.log = real_log
    alerts = [e for e in audit(b) if e["type"] == "anomaly.alert"]
    assert sorted(e["data"]["detector"] for e in alerts) == ["denial_burst", "forbidden_sweep"]
    # written inside the first attack's padded window: after its attack.evaluated, before its reply
    first_reply = [e for e in b.events if e[0] == "reply"][6][1]  # replies: commit, 5 probes, then the attacks
    alert_t = [t for ty, t in order if ty == "anomaly.alert"]
    first_eval = [t for ty, t in order if ty == "attack.evaluated"][0]
    assert all(first_eval < t < first_reply for t in alert_t)
    # and nothing for the detectors was written while a denial was being answered
    probe_replies = [e[1] for e in b.events if e[0] == "reply"][1:6]
    assert all(t > probe_replies[-1] for t in alert_t)


def test_P4A11_no_content_channel_participants_see_no_detector_event_until_sealed():
    b = bench("T-P4A11", deadline=300)
    play(b, ATTACKS)
    run = runs.Run("T-P4A11")
    assert run.state == "RUNNING"
    public = runs.monitor_view(run, trusted=False)
    assert not [e for e in public if str(e.get("type", "")).startswith("anomaly.")]
    assert "anomaly.alert" not in runs.PARTICIPANT_EVENTS and "anomaly.summary" not in runs.PARTICIPANT_EVENTS
    trusted = runs.monitor_view(run, trusted=True)
    assert len([e for e in trusted if e.get("type") == "anomaly.alert"]) == 2  # operator / reviewer: live
    b.seal(complete=True)
    after = runs.monitor_view(runs.Run("T-P4A11"), trusted=False)
    assert [e for e in after if e.get("type") == "anomaly.summary"]  # everyone, once red can no longer act


def test_P4A12_no_content_channel_red_receives_the_same_bytes_whether_or_not_a_detector_fired():
    quiet = play(bench("T-P4A12Q", deadline=300), ATTACKS, probes=False)
    noisy = play(bench("T-P4A12N", deadline=300), ATTACKS, probes=True)[len(PROBES):]
    assert [r[2] for r in quiet] == [r[2] for r in noisy]
    assert [e for e in audit_of("T-P4A12N") if e["type"] == "anomaly.alert"]
    assert not [e for e in audit_of("T-P4A12Q") if e["type"] == "anomaly.alert"]


def audit_of(rid):
    return read_jsonl(runs.Run(rid).dir / "audit.jsonl")


def test_P4A13_no_timing_channel_in_deadline_mode_every_attack_reply_leaves_at_the_deadline():
    for rid, probes in (("T-P4A13Q", False), ("T-P4A13N", True)):
        lat = [ms for _, ms, _ in play(bench(rid, deadline=300), ATTACKS, probes=probes)[len(PROBES) if probes else 0:]]
        assert all(300 <= ms < 300 + TOL_MS for ms in lat), (rid, lat)


def test_P4A14_no_timing_channel_on_denials_a_denial_never_writes_for_the_detectors(monkeypatch):
    """The fifth probe crosses both thresholds; its reply must not wait for an alert write. Make alert writes slow and
    check the denial latencies stay the same as the first four."""
    b = bench("T-P4A14", deadline=300)
    real = anomaly.log_alerts

    def slow(run, alerts):
        if alerts:
            time.sleep(0.15)
        return real(run, alerts)
    monkeypatch.setattr(anomaly, "log_alerts", slow)
    lat = [ms for _, ms, _ in play(b, ATTACKS)]
    assert max(lat[:5]) < 100, lat[:5]
    assert all(300 <= ms < 300 + TOL_MS for ms in lat[5:]), lat[5:]  # the slow write was hidden by the deadline


def test_P4A15_unpadded_alerts_wait_for_the_seal():
    b = bench("T-P4A15", bucket=0)
    play(b, ATTACKS)
    assert not [e for e in audit(b) if e["type"] == "anomaly.alert"]
    b.seal(complete=True)
    types = [e["type"] for e in audit(b)]
    assert types.count("anomaly.alert") == 2 and types.index("anomaly.summary") < types.index("run.sealed")
    assert max(i for i, t in enumerate(types) if t == "anomaly.alert") < types.index("run.sealed")


def test_P4A16_near_miss_from_real_model_output_is_detected_and_never_withheld():
    runs.create_run("T-OTHER")
    other = store.read_json(store.p("runs") / "T-OTHER" / "sealed/canary.json")["canary"]
    frag = other.split("-", 1)[1][:7]
    b = bench("T-P4A16", deadline=300, answer=lambda p: "maybe it was %s?" % frag)
    out = play(b, [("A%02d" % i, "payload %d" % i) for i in range(1, 5)], probes=False)
    assert all(json.loads(r[2])["refused"] is False for r in out)  # a fragment is below the withholding rule
    near = [e for e in audit(b) if e["type"] == "anomaly.alert" and e["data"]["detector"] == "canary_near_miss"]
    assert len(near) == 1 and other not in json.dumps(audit(b))


def test_P4A17_cutoff_spike_is_detected():
    b = bench("T-P4A17", deadline=250, model_s=1.0)
    play(b, [("A%02d" % i, "payload %d" % i) for i in range(1, 5)], probes=False)
    assert [e["data"]["detector"] for e in audit(b) if e["type"] == "anomaly.alert"] == ["model_cutoffs"]


def test_P4A18_the_seal_records_every_detector_with_its_threshold_and_count():
    b = bench("T-P4A18", deadline=300)
    play(b, ATTACKS)
    b.seal(complete=True)
    s = [e for e in audit(b) if e["type"] == "anomaly.summary"][0]["data"]
    assert set(s["detectors"]) == set(anomaly.DETECTORS)
    assert s["detectors"]["denial_burst"]["fired"] == 1 and s["detectors"]["latency_drift"]["fired"] == 0
    assert s["attacks_observed"] == len(ATTACKS) and s["denials_observed"] == 5
