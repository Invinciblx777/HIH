"""Phase 1 closeout timing experiment: same procedure as timing_eval.py, plus provenance and raw-data retention.

    AEGIS_VAR=<fresh scratch> python evaluation/timing_closeout.py --seed 20261022 --out-dir <dir>

Reuses timing_eval.py UNCHANGED for the padding runs, the held-out classifier (best single latency threshold fitted on
training runs, scored on held-out runs; grouped 5-fold by run) and the permutation test. What is new here:

  * every request and every round trip is written to a raw file (timing_eval.py kept only summaries);
  * a unique run id, UTC timestamps, per-file sha256 of the source tree, image id, host details, load before/after;
  * padding runs from the four settings are interleaved in a seeded random order, so slow drift of the host (thermal,
    desktop activity) cannot line up with one setting;
  * the CPU-contention round trip is measured in blocks of 100 whose condition order is shuffled per repetition
    (idle / neighbour limited to 1 CPU / unrestricted neighbour), each block checked for a running neighbour and for
    host CPU utilisation; percentage increase is defined below and has a block-bootstrap interval;
  * a run that fails or yields unusable data is listed under `unusable`, never dropped silently.

Pre-declared definitions (also stored in the output):
  latency_increase_pct = 100 * (median(contention samples) - median(idle samples)) / median(idle samples), pooled over
  all non-warm-up samples of the same execution; the same formula is applied to p99. p99 uses the nearest-rank rule of
  timing_eval.pcts: sorted[round(0.99 * (n - 1))].
  Round trip = wall-clock time of broker.call("model", {"op": "stats"}) measured with time.perf_counter() in the control
  plane process: request file written, polled by the model worker (~2 ms poll), reply file polled back.
  Classification latency = time.perf_counter() delta measured INSIDE the red sandbox around one `attack` call.
"""
import argparse
import hashlib
import json
import os
import platform
import random
import secrets
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
import timing_eval as te  # noqa: E402
from aegis import runtime, runs, store  # noqa: E402
from revision import code_revision  # noqa: E402

CONDITIONS = ("idle", "limited_1cpu_8proc", "unrestricted_%dproc" % (os.cpu_count() or 8))
RULES = {
    "classification": "per bucket, 20 runs x 10 attacks (5 refused, 5 answered); threshold fitted on training runs only, "
                      "scored on held-out runs (grouped 5-fold by run); majority baseline = larger class share; "
                      "permutation p from 1000 label shuffles of the full procedure; padding intervals fixed in advance "
                      "(0/100/250/500 ms) and not tuned on these observations",
    "verdict_rule": "a padded setting is 'leak detected' if its permutation p < 0.05/9 (Bonferroni over 3 executions x 3 padded "
                    "settings) in any execution; otherwise 'no leak detected (inconclusive as to absence)'; settings whose "
                    "executions disagree at uncorrected p<0.05 are 'unstable'",
    "usable_run": "run ends SEALED with complete=true without exception and returns exactly 10 observations; others are "
                  "listed in `unusable` and excluded from metrics (raw kept)",
    "rtt": "blocks of 100 timed calls after 20 discarded warm-up calls; 10 blocks per condition; condition order shuffled "
           "within each repetition; a contention block is valid only if the neighbour container is running before and after",
    "latency_increase_pct": "100*(median(contention)-median(idle))/median(idle), pooled non-warm-up samples of this "
                            "execution; same for p99; 95% interval by bootstrap over blocks (2000 resamples)",
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def source_hashes():
    files = [p for d in ("aegis", "sandbox", "evaluation", "scripts", "tests", "samples") for p in sorted((ROOT / d).rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".sh", ".json")]
    files += [ROOT / "Containerfile", ROOT / "requirements.txt"]
    return {str(p.relative_to(ROOT)): sha(p) for p in files if p.exists()}


def cpu_times():
    f = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    v = list(map(int, f))
    return sum(v), v[3] + v[4]  # total, idle+iowait


def host_snapshot():
    cpu = ""
    for ln in Path("/proc/cpuinfo").read_text().splitlines():
        if ln.startswith("model name"):
            cpu = ln.split(":", 1)[1].strip()
            break
    top = subprocess.run(["ps", "-eo", "pcpu,comm", "--sort=-pcpu", "--no-headers"], capture_output=True, text=True).stdout.splitlines()[:6]
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    return {"cpu_model": cpu, "cpus": os.cpu_count(), "governor": gov.read_text().strip() if gov.exists() else None,
            "mem_available_mb": int([ln for ln in Path("/proc/meminfo").read_text().splitlines() if ln.startswith("MemAvailable")][0].split()[1]) // 1024,
            "loadavg": os.getloadavg(), "top_processes_by_cpu_before_start": [t.strip() for t in top],
            "python": platform.python_version(), "platform": platform.platform()}


def classification(a, out, rid_prefix):
    order = [(i, b) for i in range(a.runs) for b in te.BUCKETS]
    rng = random.Random(a.seed)
    # interleave: within each repetition i every setting runs once, in shuffled order
    seq = []
    for i in range(a.runs):
        bs = list(te.BUCKETS)
        rng.shuffle(bs)
        seq += [(i, b) for b in bs]
    assert sorted(seq) == sorted(order)
    meta, raw = [], []
    for n, (i, b) in enumerate(seq):
        run_id = "TX-B%d-%02d" % (b, i + 1)
        rec = {"order_index": n, "bucket_ms": b, "rep": i, "run_id": run_id, "started_utc": datetime.now(timezone.utc).isoformat()}
        try:
            run, wall = te.do_run(run_id, b)
            obs = store.read_json(run.dir / "sealed/red_observed.json", [])
            rec.update(wall_s=round(wall, 4), state=run.state, n_obs=len(obs))
            for k, o in enumerate(obs):
                raw.append({"run_id": run_id, "bucket_ms": b, "rep": i, "seq": k, "attack_id": o["attack_id"],
                            "latency_ms": o["latency_ms"], "refused": int(bool(o["refused"]))})
            rec["complete"] = run.record.get("complete")
            if len(obs) != 10 or run.state != "SEALED" or not rec["complete"]:
                rec["unusable"] = "state=%s complete=%s n_obs=%d" % (run.state, rec["complete"], len(obs))
        except Exception as exc:  # recorded, never silently dropped
            rec["unusable"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        meta.append(rec)
        print("  [%2d/%d] %s wall=%s %s" % (n + 1, len(seq), run_id, rec.get("wall_s"), rec.get("unusable", "ok")), flush=True)
    (out / "raw_runs.json").write_text(json.dumps(meta, indent=1))
    with (out / "raw_classification.jsonl").open("w") as f:
        for r in raw:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    bad = {m["run_id"] for m in meta if "unusable" in m}
    conds = {}
    for b in te.BUCKETS:
        rows = [(r["rep"], r["latency_ms"], r["refused"]) for r in raw if r["bucket_ms"] == b and r["run_id"] not in bad]
        c = te.analyse(rows, a.seed)
        walls = [m["wall_s"] * 1000 for m in meta if m["bucket_ms"] == b and "unusable" not in m]
        c.update(bucket_ms=b, total_requests=len(rows), usable_runs=len({r[0] for r in rows}),
                 run_wall_clock_s=te.pcts(walls) if walls else None)
        conds[str(b)] = c
        print("bucket %3d: n=%d acc=%.3f baseline=%.3f p=%.4f auc=%s" % (b, len(rows), c["heldout_accuracy"], c["majority_baseline"],
                                                                         c["permutation_p"], c["auc_refused_faster"]), flush=True)
    base = conds["0"]["latency_answered"]["median_ms"]
    for c in conds.values():
        c["added_median_latency_for_answered_requests_ms"] = round(c["latency_answered"]["median_ms"] - base, 2)
    return conds, [m for m in meta if "unusable" in m]


def rtt(a, out):
    rid = "TX-RTT"
    runs.create_run(rid, tags=["timing", "rtt", "closeout"])
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    b = runs.Broker(run)
    name = "aegis-timing-rtt-model"
    runtime.launch(name, "model", [(str(b._mk_spool("model")), "/aegis/spool", "rw")], {})
    b.names["model"] = name
    b.call("model", {"op": "stats"}, timeout=30)
    hog = "aegis-timing-hog"
    flags = {CONDITIONS[1]: (runtime.hardening_flags("red"), 8), CONDITIONS[2]: (["--network", "none"], os.cpu_count() or 8)}
    rng = random.Random(a.seed + 1)
    schedule = []
    for rep in range(a.rtt_reps):
        cs = list(CONDITIONS)
        rng.shuffle(cs)
        schedule += [(rep, c) for c in cs]
    blocks, f = [], (out / "raw_rtt.jsonl").open("w")
    try:
        for n, (rep, cond) in enumerate(schedule):
            blk = {"block": n, "rep": rep, "condition": cond, "started_utc": datetime.now(timezone.utc).isoformat(), "valid": True}
            if cond != "idle":
                args, procs = flags[cond]
                subprocess.run(["podman", "run", "-d", "--rm", "--name", hog] + args + [runtime.IMAGE, "python", "-c", te.HOG % procs],
                               capture_output=True, check=True)
                time.sleep(1.0)
                blk["neighbour_running_before"] = runtime.running(hog)
            vals = []
            tot0, idle0 = cpu_times()
            for k in range(a.rtt_warmup + a.rtt_block):
                t = time.perf_counter()
                b.call("model", {"op": "stats"})
                ms = (time.perf_counter() - t) * 1000
                warm = k < a.rtt_warmup
                f.write(json.dumps({"block": n, "condition": cond, "k": k, "warmup": warm, "rtt_ms": round(ms, 4)}) + "\n")
                if not warm:
                    vals.append(ms)
            tot1, idle1 = cpu_times()
            blk["host_cpu_busy_pct"] = round(100 * (1 - (idle1 - idle0) / max(1, tot1 - tot0)), 1)
            blk["loadavg_after_block"] = os.getloadavg()
            if cond != "idle":
                blk["neighbour_running_after"] = runtime.running(hog)
                runtime.stop(hog)
                blk["valid"] = bool(blk["neighbour_running_before"] and blk["neighbour_running_after"])
            blk["median_ms"], blk["n"] = round(statistics.median(vals), 3), len(vals)
            blocks.append((blk, vals))
            print("  rtt block %2d %-24s median=%.2f busy=%s%% valid=%s" % (n, cond, blk["median_ms"], blk["host_cpu_busy_pct"], blk["valid"]), flush=True)
    finally:
        f.close()
        runtime.stop(hog)
        runtime.stop(name)
        run.update(state="FAILED", note="instrumentation run, not an evaluation")
    (out / "rtt_blocks.json").write_text(json.dumps([b_ for b_, _ in blocks], indent=1))
    return summarise_rtt(blocks, a.seed + 2), [b_ for b_, _ in blocks if not b_["valid"]]


def summarise_rtt(blocks, seed):
    by = {c: [v for blk, v in blocks if blk["condition"] == c and blk["valid"]] for c in CONDITIONS}
    pooled = {c: [x for v in vs for x in v] for c, vs in by.items()}
    res = {c: dict(te.pcts(pooled[c]), blocks=len(by[c]), block_medians_ms=[round(statistics.median(v), 3) for v in by[c]])
           for c in CONDITIONS if pooled[c]}
    rng = random.Random(seed)
    idle = by["idle"]

    def q99(v):
        s = sorted(v)
        return s[min(len(s) - 1, int(round(0.99 * (len(s) - 1))))]
    for c in CONDITIONS[1:]:
        if not by[c] or not idle:
            continue
        inc_med = 100 * (res[c]["median_ms"] - res["idle"]["median_ms"]) / res["idle"]["median_ms"]
        inc_p99 = 100 * (res[c]["p99_ms"] - res["idle"]["p99_ms"]) / res["idle"]["p99_ms"]
        bm, bp = [], []
        for _ in range(2000):
            i_ = [x for j in (rng.choice(idle) for _ in idle) for x in j]
            c_ = [x for j in (rng.choice(by[c]) for _ in by[c]) for x in j]
            bm.append(100 * (statistics.median(c_) - statistics.median(i_)) / statistics.median(i_))
            bp.append(100 * (q99(c_) - q99(i_)) / q99(i_))
        bm.sort(); bp.sort()
        res[c]["increase_vs_idle"] = {"median_pct": round(inc_med, 1), "median_pct_ci95_block_bootstrap": [round(bm[49], 1), round(bm[1949], 1)],
                                      "p99_pct": round(inc_p99, 1), "p99_pct_ci95_block_bootstrap": [round(bp[49], 1), round(bp[1949], 1)]}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--rtt-reps", type=int, default=10)
    ap.add_argument("--rtt-block", type=int, default=100)
    ap.add_argument("--rtt-warmup", type=int, default=20)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=False)
    exec_id = "TX-%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(3))
    t0 = time.time()
    print("execution", exec_id, "seed", a.seed, flush=True)
    res = {"execution_id": exec_id, "argv": sys.argv, "started_utc": datetime.fromtimestamp(t0, timezone.utc).isoformat(),
           "seed": a.seed, "status": "RUNNING", "config": {k: v for k, v in vars(a).items() if k != "out_dir"} | {
               "padding_intervals_ms": list(te.BUCKETS), "attacks_per_run": 10, "classes_per_run": {"refused": 5, "answered": 5},
               "model": "stub worker, fixed ~40 ms sleep", "aegis_var": os.environ.get("AEGIS_VAR")},
           "rules": RULES, "code_revision": code_revision(), "source_sha256": source_hashes(),
           "host": host_snapshot()}
    (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))  # a crashed execution leaves a visible RUNNING file
    try:
        res["sandbox_image_id"] = runtime.build_image(ROOT)
        res["environment"] = runtime.environment()
        res["conditions"], res["unusable"] = classification(a, out, exec_id)
        print("rtt", flush=True)
        res["broker_mailbox_rtt"], res["unusable_rtt_blocks"] = rtt(a, out)
        res["status"] = "COMPLETE"
    except BaseException as exc:
        res["status"] = "FAILED"
        res["failure"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
        raise
    finally:
        res["host"]["loadavg_after"] = os.getloadavg()
        res["finished_utc"] = datetime.now(timezone.utc).isoformat()
        res["wall_clock_s"] = round(time.time() - t0, 1)
        res["raw_files_sha256"] = {n: sha(out / n) for n in ("raw_runs.json", "raw_classification.jsonl", "raw_rtt.jsonl", "rtt_blocks.json") if (out / n).exists()}
        res["confounders"] = [
            "label (refused) is determined by attack id: 10 distinct payloads, 5 refused / 5 answered per run",
            "stub model latency is a fixed ~40 ms sleep; a real model's latency varies and can cross bucket boundaries (not covered)",
            "single host, laptop CPU, desktop session running, SELinux enforcing, rootless Podman, file-mailbox polling ~2 ms (RTT quantised)",
            "runs are sequential; no concurrent tenants during the classification experiment",
            "a single-threshold classifier is a weak adversary; a stronger one or a far larger n could extract more",
            "the 100/250/500 ms settings were fixed before measurement; 250 ms is the shipped default chosen on 15 Oct data",
        ]
        (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))
    print("status", res["status"], "wall", res["wall_clock_s"], "s")


if __name__ == "__main__":
    main()
