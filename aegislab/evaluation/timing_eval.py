"""Timing side-channel and resource-interference evaluation (replaces the in-sample E7 classifier).

    AEGIS_VAR=<scratch> python evaluation/timing_eval.py --runs 20 --out evidence/validation_2026-10-22/timing.json

What red can observe is the round-trip latency of each answer. If refused and answered requests have different
latency, red learns the defence verdict without being told. The existing mitigation answers on bucket boundaries.

Method (all numbers in the output come from this script):
  * conditions = timing bucket in {0, 100, 250, 500} ms, `--runs` independent runs each (10 attacks per run)
  * label = whether the request was refused; feature = latency red observed (ms); stub model, ~40 ms inference
  * classifier = best single threshold chosen on TRAINING runs only, scored on HELD-OUT runs (grouped k-fold by run,
    so no run contributes to both training and test); the old report scored the same data it fitted
  * reported: n per class, majority-class baseline, accuracy and balanced accuracy with Wilson 95% CI,
    AUC (probability a random refused request is faster than a random answered one; 0.5 = no information),
    permutation-test p-value for the held-out accuracy (labels shuffled, same procedure, fixed seed)
  * cost on legitimate traffic = added median latency of ANSWERED requests and wall-clock per run vs bucket 0
  * broker mailbox round trip (idle / CPU hog limited to 1 CPU / CPU hog unlimited): median, p90, p95, p99, max

Known confounders, repeated in the output: refusal is a function of the attack id, so label and payload are
confounded (10 distinct payloads); the stub model's latency is a fixed sleep, a real model's is not (a real
model's variable latency can cross bucket boundaries, which this experiment does not cover); laptop CPU with frequency
scaling and a desktop session running; file-mailbox polling at ~2-3 ms; single host.
"""
import argparse
import json
import math
import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "evaluation"))
from aegis import runtime, runs, store  # noqa: E402
from revision import code_revision  # noqa: E402

BUCKETS = (0, 100, 250, 500)
HOG = "import multiprocessing as m\ndef f():\n    while True: pass\nfor _ in range(%d): m.Process(target=f).start()"


def pcts(v):
    s = sorted(v)

    def q(p):
        return round(s[min(len(s) - 1, int(round(p * (len(s) - 1))))], 2)
    return {"n": len(v), "median_ms": round(statistics.median(v), 2), "p90_ms": q(0.90), "p95_ms": q(0.95),
            "p99_ms": q(0.99), "max_ms": round(max(v), 2), "min_ms": round(min(v), 2)}


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(c - h, 3), round(c + h, 3)]


def best_threshold(xs, ys):
    """Single threshold on latency maximising balanced accuracy on the training data. y=1 means refused."""
    pts = sorted(set(xs))
    cands = [(a + b) / 2 for a, b in zip(pts, pts[1:])] or [pts[0]]
    best, best_t, best_sign = -1, cands[0], 1
    for t in cands:
        for sign in (1, -1):  # sign 1: faster than t -> refused; -1: slower than t -> refused
            pred = [int((x < t) if sign == 1 else (x >= t)) for x in xs]
            tp = sum(p and y for p, y in zip(pred, ys)); tn = sum((not p) and (not y) for p, y in zip(pred, ys))
            P, N = sum(ys), len(ys) - sum(ys)
            bal = (tp / P if P else 0) / 2 + (tn / N if N else 0) / 2
            if bal > best:
                best, best_t, best_sign = bal, t, sign
    return best_t, best_sign


def auc(xs, ys):
    """P(refused request is faster than answered request); ties count half."""
    pos = [x for x, y in zip(xs, ys) if y]
    neg = [x for x, y in zip(xs, ys) if not y]
    if not pos or not neg:
        return None
    wins = sum((p < n) + 0.5 * (p == n) for p in pos for n in neg)
    return round(wins / (len(pos) * len(neg)), 3)


def grouped_cv(rows, k, rng):
    """rows: list of (run_index, latency, refused). Returns held-out predictions as (pred, truth)."""
    groups = sorted({r[0] for r in rows})
    rng.shuffle(groups)
    folds = [groups[i::k] for i in range(k)]
    out = []
    for fold in folds:
        test = [r for r in rows if r[0] in fold]
        train = [r for r in rows if r[0] not in fold]
        t, sign = best_threshold([r[1] for r in train], [r[2] for r in train])
        for _, x, y in test:
            out.append((int((x < t) if sign == 1 else (x >= t)), y))
    return out


def score(pairs):
    n = len(pairs)
    acc = sum(p == y for p, y in pairs) / n
    P = [p for p, y in pairs if y]
    N = [p for p, y in pairs if not y]
    bal = (sum(P) / len(P) + sum(1 - p for p in N) / len(N)) / 2 if P and N else None
    return acc, bal


def analyse(rows, seed, k=5, perms=1000):
    rng = random.Random(seed)
    ys = [r[2] for r in rows]
    n_ref, n_ans = sum(ys), len(ys) - sum(ys)
    pairs = grouped_cv(rows, k, random.Random(seed))
    acc, bal = score(pairs)
    # permutation test: shuffle labels across requests, repeat the full grouped-CV procedure
    ge = 0
    for _ in range(perms):
        shuffled = [r[2] for r in rows]
        rng.shuffle(shuffled)
        prow = [(r[0], r[1], s) for r, s in zip(rows, shuffled)]
        a, _ = score(grouped_cv(prow, k, random.Random(rng.random())))
        ge += a >= acc
    xs = [r[1] for r in rows]
    return {"n_refused": n_ref, "n_answered": n_ans, "majority_baseline": round(max(n_ref, n_ans) / len(rows), 3),
            "heldout_accuracy": round(acc, 3), "heldout_accuracy_ci95": wilson(round(acc * len(pairs)), len(pairs)),
            "heldout_balanced_accuracy": None if bal is None else round(bal, 3), "auc_refused_faster": auc(xs, ys),
            "permutation_p": round((ge + 1) / (perms + 1), 4), "permutations": perms, "folds": k,
            "latency_refused": pcts([r[1] for r in rows if r[2]]) if n_ref else None,
            "latency_answered": pcts([r[1] for r in rows if not r[2]]) if n_ans else None}


def do_run(rid, bucket):
    runs.create_run(rid, timing_bucket_ms=bucket, tags=["timing", "bucket%d" % bucket])
    runs.freeze(rid)
    t = time.perf_counter()
    runs.start(rid, wait=True)
    return runs.Run(rid), time.perf_counter() - t


def rtt_conditions(n):
    rid = "TIM-RTT"
    runs.create_run(rid, tags=["timing", "rtt"])
    runs.freeze(rid)
    run = runs.Run(rid)
    run.update(state="RUNNING")
    b = runs.Broker(run)
    name = "aegis-timing-rtt-model"
    runtime.launch(name, "model", [(str(b._mk_spool("model")), "/aegis/spool", "rw")], {})
    b.names["model"] = name
    b.call("model", {"op": "stats"}, timeout=30)

    def measure():
        v = []
        for _ in range(n):
            t = time.perf_counter()
            b.call("model", {"op": "stats"})
            v.append((time.perf_counter() - t) * 1000)
        return pcts(v)

    res = {"idle": measure()}
    hog = "aegis-timing-hog"

    def with_hog(args, procs):
        subprocess.run(["podman", "run", "-d", "--rm", "--name", hog] + args + [runtime.IMAGE, "python", "-c", HOG % procs],
                       capture_output=True, check=True)
        time.sleep(1.0)
        try:
            return measure()
        finally:
            runtime.stop(hog)
    res["cpu_hog_limited_1cpu_8proc"] = with_hog(runtime.hardening_flags("red"), 8)
    res["cpu_hog_unlimited_%dproc" % (os.cpu_count() or 8)] = with_hog(["--network", "none"], os.cpu_count() or 8)
    runtime.stop(name)
    run.update(state="FAILED", note="instrumentation run, not an evaluation")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--rtt", type=int, default=500)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    t0 = time.time()
    runtime.build_image(ROOT)
    load0 = os.getloadavg()
    res = {"started_at": t0, "code_revision": code_revision(), "seed": a.seed, "runs_per_condition": a.runs, "attacks_per_run": 10,
           "environment": {**runtime.environment(), "loadavg_before": load0}, "conditions": {}}
    base_wall = None
    for bucket in BUCKETS:
        rows, walls, answered_all = [], [], []
        for i in range(a.runs):
            run, wall = do_run("TIM-B%d-%02d" % (bucket, i + 1), bucket)
            walls.append(wall)
            for o in store.read_json(run.dir / "sealed/red_observed.json", []):
                rows.append((i, o["latency_ms"], int(bool(o["refused"]))))
        cond = analyse(rows, a.seed)
        cond.update({"bucket_ms": bucket, "run_wall_clock_s": pcts([w * 1000 for w in walls]),
                     "total_requests": len(rows)})
        res["conditions"][str(bucket)] = cond
        print("bucket", bucket, cond["heldout_accuracy"], cond["auc_refused_faster"], cond["permutation_p"])
    base = res["conditions"]["0"]["latency_answered"]["median_ms"]
    for b, c in res["conditions"].items():
        c["added_median_latency_for_answered_requests_ms"] = round(c["latency_answered"]["median_ms"] - base, 2)
    print("rtt")
    res["broker_mailbox_rtt"] = rtt_conditions(a.rtt)
    res["environment"]["loadavg_after"] = os.getloadavg()
    res["finished_at"] = time.time()
    res["wall_clock_s"] = round(res["finished_at"] - t0, 1)
    res["confounders"] = [
        "label (refused) is determined by attack id: 10 distinct payloads, 5 refused / 5 answered per run; results describe these payloads",
        "stub model latency is a fixed ~40 ms sleep; a real model's latency varies and can cross bucket boundaries (not covered)",
        "laptop CPU with frequency scaling, desktop session running, SELinux enforcing, rootless Podman, file-mailbox polling ~2-3 ms",
        "runs are sequential on one host; no concurrent tenants during the classification experiment",
        "a single-threshold classifier is a weak adversary; a stronger one (or a far larger n) could extract more",
    ]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2, sort_keys=True))
    print(json.dumps({k: {x: v[x] for x in ("heldout_accuracy", "heldout_accuracy_ci95", "majority_baseline", "auc_refused_faster", "permutation_p",
                                              "added_median_latency_for_answered_requests_ms")}
                      for k, v in res["conditions"].items()}, indent=1))


if __name__ == "__main__":
    main()
