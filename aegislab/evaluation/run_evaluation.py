"""AegisLab measured evaluation.

Runs real runs through the prototype (rootless Podman containers, stub model
worker) and writes evidence/results.json and evidence/RESULTS.md.

    AEGIS_VAR=<scratch dir> python evaluation/run_evaluation.py --out evidence/<dated folder> [--runs 10]

Every number in RESULTS.md comes from this script's output on the machine it
ran on. Re-running produces new measurements.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from aegis import api, runtime, runs, store  # noqa: E402
from aegis.audit import read_jsonl  # noqa: E402
from aegis.verify_cli import TAMPER_MODES, tamper_test  # noqa: E402

OUT = ROOT / "evidence"  # replaced by --out in main(); the submitted results.json / RESULTS.md here are never overwritten
HOG = "import multiprocessing as m\ndef f():\n    while True: pass\nfor _ in range(%d): m.Process(target=f).start()"


def pct(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def summary(values):
    return {"n": len(values), "median_ms": round(statistics.median(values), 2),
            "p95_ms": round(pct(values, 0.95), 2), "min_ms": round(min(values), 2), "max_ms": round(max(values), 2)}


def do_run(run_id, bucket_ms=250, reset="fresh-container", tags=()):
    runs.create_run(run_id, timing_bucket_ms=bucket_ms, reset_strategy=reset, tags=list(tags))
    runs.freeze(run_id)
    runs.start(run_id, wait=True)
    return runs.Run(run_id)


def exp_freeze():
    """E1: configuration cannot change after freeze; a modified frozen file fails closed."""
    rid = "EVAL-FREEZE-1"
    runs.create_run(rid, tags=["eval", "freeze"])
    runs.freeze(rid)
    denied = 0
    for i in range(5):
        try:
            runs.update_defence_config(rid, {"version": "changed-%d" % i, "input_patterns": [], "output_patterns": []})
        except runs.GateError:
            denied += 1
    # tamper with the frozen file on disk (simulates a write that bypassed the API)
    rid2 = "EVAL-FREEZE-2"
    runs.create_run(rid2, tags=["eval", "freeze"])
    runs.freeze(rid2)
    f = runs.Run(rid2).dir / "frozen/defence_config.json"
    os.chmod(f, 0o644)
    f.write_text(f.read_text().replace("developer mode", "developer-mode-disabled"))
    runs.start(rid2, wait=True)
    state2 = runs.Run(rid2).state
    att = next(e["data"] for e in read_jsonl(runs.Run(rid2).dir / "audit.jsonl") if e["type"] == "defence.attested")
    runs.start(rid, wait=True)
    runs.release(rid)
    return {"api_changes_after_freeze": {"attempts": 5, "denied": denied},
            "modified_frozen_file": {"run": rid2, "final_state": state2, "attestation_matches": att["matches_manifest"]}}


def exp_rtt(n=200):
    """IPC cost of one broker mailbox hop (round trip to an idle model worker)."""
    rid = "EVAL-RTT"
    runs.create_run(rid, tags=["eval", "rtt"])
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    b = runs.Broker(run)
    name = "aegis-eval-rtt-model"
    runtime.launch(name, "model", [(str(b._mk_spool("model")), "/aegis/spool", "rw")], {})
    b.names["model"] = name
    b.call("model", {"op": "stats"}, timeout=30)
    rtt = []
    for _ in range(n):
        t = time.perf_counter()
        b.call("model", {"op": "stats"})
        rtt.append((time.perf_counter() - t) * 1000)
    # noisy neighbour: a CPU hog container with the same limits as a red sandbox
    hog = "aegis-eval-hog"
    subprocess.run(["podman", "run", "-d", "--rm", "--name", hog] + runtime.hardening_flags("red") +
                   [runtime.IMAGE, "python", "-c",
                    HOG % 8],
                   capture_output=True, check=True)
    time.sleep(1.0)
    rtt_hog = []
    for _ in range(n):
        t = time.perf_counter()
        b.call("model", {"op": "stats"})
        rtt_hog.append((time.perf_counter() - t) * 1000)
    runtime.stop(hog)
    subprocess.run(["podman", "run", "-d", "--rm", "--name", hog, "--network", "none", runtime.IMAGE, "python", "-c",
                    HOG % (os.cpu_count() or 8)], capture_output=True, check=True)
    time.sleep(1.0)
    rtt_unlimited = []
    for _ in range(n):
        t = time.perf_counter()
        b.call("model", {"op": "stats"})
        rtt_unlimited.append((time.perf_counter() - t) * 1000)
    runtime.stop(hog)
    runtime.stop(name)
    run.update(state="FAILED", note="instrumentation run, not an evaluation")
    return {"idle": summary(rtt), "hog_limited_1cpu_8proc": summary(rtt_hog),
            "hog_unlimited_%dproc" % (os.cpu_count() or 8): summary(rtt_unlimited)}


def markdown(r):
    env = r["environment"]
    e1, e2, e3, e4, e5, e6, e8 = (r["E1_freeze"], r["E2_cross_tenant"], r["E3_E7_latency_timing"], r["E4_canary"],
                                  r["E5_audit_tamper"], r["E6_release_gate"], r["E8_monitoring_redaction"])
    rtt = r["E3_mailbox_rtt_and_interference"]
    unl = next(k for k in rtt if k.startswith("hog_unlimited"))
    fr, rc = e4["fresh_container_reset"], e4["reuse_control_no_reset"]
    np_, pd = e3["red_observed_no_padding"], e3["red_observed_250ms_buckets"]
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(r["started_at"]))
    L = [
        "# AegisLab prototype: measured results", "",
        "Label: **Measured result** on the local prototype. Generated by `evaluation/run_evaluation.py` on %s "
        "(wall clock %.0f s). The model worker is a deterministic stub, not an LLM. Results describe this "
        "configuration on this host only; they are not proof of confidentiality." % (when, r["wall_clock_s"]), "",
        "## Environment", "",
        "- Host: %s CPUs, kernel %s, cgroups %s, SELinux %s" % (env["cpus"], env["kernel"], env["cgroups"],
                                                               "enforcing" if env["selinux"] else "off"),
        "- Runtime: Podman %s (rootless=%s), %s; seccomp profile %s" % (env["podman"], env["rootless"],
                                                                     env["oci_runtime_version"], env["seccomp_profile"]),
        "- cpuset controller delegated to rootless user: %s (so per-tenant CPU pinning was %s)" % (
            env["cpuset_delegated"], "applied" if env["cpuset_delegated"] else "NOT applied"),
        "- Runs per condition: %d. Each run: 10 synthetic attacks + 5 forbidden requests." % r["runs_per_condition"], "",
        "| ID | Test | Method | n | Outcome | Limits |", "|---|---|---|---|---|---|",
        "| E1 | Frozen configuration | 5 API config changes after freeze; frozen file edited on disk before start "
        "| 5 + 1 run | %d/5 denied; edited file: attestation match=%s, run state %s (fail closed) "
        "| Host-level writer with broker privileges could also rewrite the manifest |" % (
            e1["api_changes_after_freeze"]["denied"], e1["modified_frozen_file"]["attestation_matches"],
            e1["modified_frozen_file"]["final_state"]),
        "| E2 | Cross-tenant access | Red sandbox sends forbidden broker ops (read blue config, read verdicts, "
        "release, uncommitted attack, spoofed tenant) and self-checks network/paths from inside | %d requests, %d connects, "
        "%d path checks | %d/%d denied; %d/%d connects failed; %d/%d foreign paths absent; /proc: %s "
        "| Tests known paths and ops; kernel exploits and runtime escapes are out of scope |" % (
            e2["forbidden_broker_requests"]["attempts"], e2["network_connect_attempts"]["attempts"],
            e2["foreign_paths_checked"]["checks"], e2["forbidden_broker_requests"]["denied"],
            e2["forbidden_broker_requests"]["attempts"], e2["network_connect_attempts"]["failed"],
            e2["network_connect_attempts"]["attempts"], e2["foreign_paths_checked"]["absent"],
            e2["foreign_paths_checked"]["checks"], ", ".join(e2["proc_status_observed"])),
        "| E3 | Broker overhead | Mailbox round trip to idle worker; broker compute per attack without padding "
        "| %d RTT; %d attacks | RTT median %.2f ms (p95 %.2f); per-attack compute median %.1f ms incl. 40 ms stub delay "
        "| File-mailbox polling; not tuned for throughput |" % (
            rtt["idle"]["n"], e3["broker_compute_per_attack_no_padding"]["n"], rtt["idle"]["median_ms"],
            rtt["idle"]["p95_ms"], e3["broker_compute_per_attack_no_padding"]["median_ms"]),
        "| E4 | Cross-run canary leakage | Each run plants a fresh canary and probes for earlier ones. Control: same "
        "worker reused without reset | %d fresh runs; %d control runs | Fresh: %d runs with leak, cache entries at start "
        "all 0. Control: %d/%d runs leaked (%d canaries), showing the probe detects reuse "
        "| Stub emulates a prompt cache; real KV-cache/GPU state not tested |" % (
            fr["runs"], rc["runs"], fr["runs_with_leak"], rc["runs_with_leak"], rc["runs"], rc["leaked_canaries"]),
        "| E5 | Audit tamper detection | 6 tamper types applied to copies of released logs, verified against "
        "reviewer-held checkpoints | %d logs per type | clean %d/%d pass; modify %d, delete %d, reorder %d, truncate %d, "
        "rehash %d detected; truncate with only freeze checkpoint retained: %d detected "
        "| Compromised broker can log falsely before signing; gap shown by last case |" % (
            e5["modify"]["trials"], e5["untampered_verify_pass"]["pass"], e5["untampered_verify_pass"]["runs"],
            e5["modify"]["detected"], e5["delete"]["detected"], e5["reorder"]["detected"], e5["truncate"]["detected"],
            e5["rehash"]["detected"], e5["truncate_unprotected"]["detected"]),
        "| E6 | Result gate | API calls by each role before/after seal and release | 6 checks + %d releases "
        "| blue artifacts before release %s; red release %s; observer evidence %s; operator release %s; reviewer before "
        "seal %s; reviewer after seal %d/%d released; blue artifacts after release %s "
        "| Local demo tokens, not SSO |" % (
            e6["reviewer_release_after_seal"]["of"], e6["blue_participant_artifacts_before_release"],
            e6["red_participant_release"], e6["observer_evidence_before_release"], e6["operator_release"],
            e6["reviewer_release_before_seal"], e6["reviewer_release_after_seal"]["released"],
            e6["reviewer_release_after_seal"]["of"], e6["blue_participant_artifacts_after_release"]),
        "| E7 | Timing side channel | Red-observed latency, refused vs answered; midpoint-threshold classifier "
        "| %d + %d (no padding), %d + %d (250 ms) | Accuracy %.2f without padding vs %.2f with 250 ms buckets "
        "(0.5 = chance). Medians %.1f/%.1f ms vs %.1f/%.1f ms | Simple classifier only; residual jitter remains |" % (
            np_["blocked"]["n"], np_["allowed"]["n"], pd["blocked"]["n"], pd["allowed"]["n"],
            np_["threshold_classifier_accuracy"], pd["threshold_classifier_accuracy"],
            np_["blocked"]["median_ms"], np_["allowed"]["median_ms"], pd["blocked"]["median_ms"],
            pd["allowed"]["median_ms"]),
        "| E8 | Monitoring redaction | Search the monitoring API output of every run for payload/output prefixes and "
        "canaries | %d runs, %d events, %d strings | %d occurrences | Metadata (timing, counts) still visible |" % (
            e8["runs"], e8["monitor_events"], e8["distinct_payloads_and_outputs_searched"], e8["occurrences_found"]),
        "| E9 | Resource interference | Mailbox RTT while a CPU hog runs with red limits (1 CPU) and without limits "
        "| %d each | median %.2f ms idle, %.2f ms limited hog, %.2f ms unlimited hog | CPU only; cache and memory-"
        "bandwidth contention not measured; RTT resolution ~2 ms |" % (
            rtt["idle"]["n"], rtt["idle"]["median_ms"], rtt["hog_limited_1cpu_8proc"]["median_ms"], rtt[unl]["median_ms"]),
        "", "Raw numbers: `results.json`.", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--out", required=True, help="output folder; must not be the submitted evidence/ folder itself")
    a = ap.parse_args()
    global OUT
    OUT = Path(a.out).resolve()
    if OUT == (ROOT / "evidence").resolve():
        sys.exit("refusing to write into the submitted evidence/ folder; use e.g. --out evidence/validation_<date>")
    OUT.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    print("building image", runtime.build_image(ROOT))
    sys.path.insert(0, str(ROOT / "evaluation"))
    from revision import code_revision
    results = {"started_at": t_start, "code_revision": code_revision(), "environment": runtime.environment(), "runs_per_condition": a.runs}

    print("E1 freeze")
    results["E1_freeze"] = exp_freeze()

    print("E3 fresh runs, bucket 250 ms")
    fresh = [do_run("EVAL-F%02d" % i, 250, tags=["eval", "fresh"]) for i in range(1, a.runs + 1)]
    print("E3 fresh runs, no timing bucket")
    nobucket = [do_run("EVAL-Z%02d" % i, 0, tags=["eval", "no-padding"]) for i in range(1, a.runs + 1)]
    print("E4 reuse control")
    runtime.stop(runs.SHARED_WORKER)
    reuse = [do_run("EVAL-R%02d" % i, 250, reset="reuse-control", tags=["eval", "control"]) for i in range(1, a.runs + 1)]
    runtime.stop(runs.SHARED_WORKER)
    all_runs = fresh + nobucket + reuse

    # API-level gate checks before release, using one sealed run
    client = TestClient(api.app)
    tok = store.tokens()
    gate_run = fresh[0].id
    gate = {
        "blue_participant_artifacts_before_release": client.get(
            "/api/runs/%s/artifacts" % gate_run, headers={"X-Aegis-Token": tok["blue_participant"]}).status_code,
        "red_participant_release": client.post(
            "/api/runs/%s/release" % gate_run, headers={"X-Aegis-Token": tok["red_participant"]}).status_code,
        "observer_evidence_before_release": client.get("/api/runs/%s/evidence" % gate_run).status_code,
        "operator_release": client.post(
            "/api/runs/%s/release" % gate_run, headers={"X-Aegis-Token": tok["operator"]}).status_code,
    }
    early = "EVAL-EARLY"
    runs.create_run(early, tags=["eval", "gate"])
    runs.freeze(early)
    gate["reviewer_release_before_seal"] = client.post(
        "/api/runs/%s/release" % early, headers={"X-Aegis-Token": tok["reviewer"]}).status_code
    released = 0
    for r in all_runs:
        if r.state == "SEALED":
            res = client.post("/api/runs/%s/release" % r.id, headers={"X-Aegis-Token": tok["reviewer"]})
            released += res.status_code == 200
    gate["reviewer_release_after_seal"] = {"released": released, "of": len(all_runs)}
    gate["blue_participant_artifacts_after_release"] = client.get(
        "/api/runs/%s/artifacts" % gate_run, headers={"X-Aegis-Token": tok["blue_participant"]}).status_code
    results["E6_release_gate"] = gate

    # E2 cross-tenant access
    denied, probes, net_fail, net_total, paths_absent, paths_total, caps = 0, 0, 0, 0, 0, 0, set()
    for r in all_runs:
        audit = read_jsonl(r.dir / "audit.jsonl")
        probes += 5
        denied += sum(1 for e in audit if e["type"] == "policy.denied" and e["actor"] == "broker")
        for c in store.read_json(r.dir / "sealed/red_selfcheck.json", []):
            if c["check"].startswith("tcp"):
                net_total += 1
                net_fail += c["result"] == "failed"
            if c["check"].startswith("path"):
                paths_total += 1
                paths_absent += c["result"] == "absent"
            if c["check"].startswith("proc"):
                caps.add("%s=%s" % (c["check"][5:], c["result"]))
    applied = store.read_json(fresh[0].dir / "sealed/runtime_applied.json")
    results["E2_cross_tenant"] = {"forbidden_broker_requests": {"attempts": probes, "denied": denied},
                                  "network_connect_attempts": {"attempts": net_total, "failed": net_fail},
                                  "foreign_paths_checked": {"checks": paths_total, "absent": paths_absent},
                                  "proc_status_observed": sorted(caps), "runtime_applied_example": applied}

    # E3 latency and E7 timing channel
    def classes(rs):
        blocked, allowed = [], []
        for r in rs:
            for o in store.read_json(r.dir / "sealed/red_observed.json", []):
                (blocked if o["refused"] else allowed).append(o["latency_ms"])
        return blocked, allowed

    def separability(blocked, allowed):
        thr = (statistics.median(blocked) + statistics.median(allowed)) / 2
        correct = sum(1 for x in blocked if x < thr) + sum(1 for x in allowed if x >= thr)
        return round(correct / (len(blocked) + len(allowed)), 3)

    b0, a0 = classes(nobucket)
    b250, a250 = classes(fresh)
    compute = [x["compute_ms"] for r in nobucket for x in read_jsonl(r.dir / "sealed/artifacts.jsonl")]
    results["E3_E7_latency_timing"] = {
        "red_observed_no_padding": {"blocked": summary(b0), "allowed": summary(a0),
                                    "threshold_classifier_accuracy": separability(b0, a0)},
        "red_observed_250ms_buckets": {"blocked": summary(b250), "allowed": summary(a250),
                                       "threshold_classifier_accuracy": separability(b250, a250)},
        "broker_compute_per_attack_no_padding": summary(compute),
        "stub_inference_delay_ms": 40,
    }
    print("E3 mailbox RTT and interference")
    results["E3_mailbox_rtt_and_interference"] = exp_rtt()

    # E4 canary
    def canary_stats(rs):
        leaks = 0
        runs_with_leak = 0
        for r in rs:
            n = sum(len(x["canary_leaks"]) for x in read_jsonl(r.dir / "sealed/artifacts.jsonl"))
            leaks += n
            runs_with_leak += n > 0
        starts = [r.record.get("model_cache_at_start") for r in rs]
        return {"runs": len(rs), "runs_with_leak": runs_with_leak, "leaked_canaries": leaks,
                "cache_entries_at_start": starts}
    results["E4_canary"] = {"fresh_container_reset": canary_stats(fresh + nobucket),
                            "reuse_control_no_reset": canary_stats(reuse)}

    # E5 tamper
    tam = {}
    released_runs = [r for r in all_runs if r.state == "RELEASED"]
    for mode in TAMPER_MODES:
        det = 0
        for r in released_runs:
            m = store.read_json(r.dir / "manifest.json")
            res = tamper_test(read_jsonl(r.dir / "audit.jsonl"), read_jsonl(store.p("reviewer_vault", r.id + ".jsonl")),
                              m["signing_public_key"], mode)
            det += res["detected"]
        tam[mode] = {"trials": len(released_runs), "detected": det, "description": TAMPER_MODES[mode]}
    clean = sum(runs.verify_run(r.id)["ok"] for r in released_runs)
    results["E5_audit_tamper"] = {"untampered_verify_pass": {"runs": len(released_runs), "pass": clean}, **tam}

    # E8 monitoring redaction
    payloads = set()
    for r in all_runs:
        for x in read_jsonl(r.dir / "sealed/artifacts.jsonl"):
            payloads.add(x["payload"])
            if x["model_output"]:
                payloads.add(x["model_output"])
    hits, events = 0, 0
    for r in all_runs:
        body = client.get("/api/runs/%s/events" % r.id).text
        events += len(read_jsonl(r.dir / "monitor.jsonl"))
        hits += sum(1 for p in payloads if p[:24] in body)
        hits += body.count("CANARY-")
    results["E8_monitoring_redaction"] = {"runs": len(all_runs), "monitor_events": events,
                                          "distinct_payloads_and_outputs_searched": len(payloads),
                                          "occurrences_found": hits}
    results["finished_at"] = time.time()
    results["wall_clock_s"] = round(results["finished_at"] - t_start, 1)
    (OUT / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True))
    (OUT / "RESULTS.md").write_text(markdown(results))
    print(json.dumps(results, indent=1)[:6000])


if __name__ == "__main__":
    main()
