"""Combine timing_closeout.py executions without averaging the individual runs away.

    python evaluation/timing_aggregate.py --out aggregate.json EXEC_DIR [EXEC_DIR ...]

Reads each execution's result.json and RAW files only. Checks the raw files against the sha256 recorded at run time,
then reports (a) every execution side by side, (b) pooled held-out counts, (c) a leave-one-execution-out transfer test
(threshold fitted on the other executions, scored on this one: no observation is used for both), (d) the verdict
for each padding setting under the rule below, (e) round-trip latency per execution and the spread between executions.

Verdict rule (fixed before the first result was inspected; Bonferroni family = executions x padded settings):
  leak detected                         any execution has permutation p < 0.05 / (executions * 3)
  leak likely                           not detected, but every execution has p < 0.05
  unstable                              not detected; some executions p < 0.05 and others not
  no leak detected (inconclusive)       every execution has p >= 0.05; absence of evidence, not evidence of absence
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
import timing_eval as te  # noqa: E402

CONDS = ("idle", "limited_1cpu_8proc", "unrestricted_16proc")


def load_exec(d):
    d = Path(d)
    res = json.loads((d / "result.json").read_text())
    for name, want in res.get("raw_files_sha256", {}).items():
        got = hashlib.sha256((d / name).read_bytes()).hexdigest()
        if got != want:
            raise SystemExit("raw file changed since the run: %s/%s" % (d, name))
    cls = [json.loads(x) for x in (d / "raw_classification.jsonl").read_text().splitlines() if x]
    rtt = [json.loads(x) for x in (d / "raw_rtt.jsonl").read_text().splitlines() if x]
    blocks = json.loads((d / "rtt_blocks.json").read_text())
    return {"dir": d, "res": res, "cls": cls, "rtt": rtt, "blocks": blocks,
            "bad_runs": {m["run_id"] for m in json.loads((d / "raw_runs.json").read_text()) if "unusable" in m}}


def rows_of(ex, bucket):
    return [(r["rep"], r["latency_ms"], r["refused"]) for r in ex["cls"] if r["bucket_ms"] == bucket and r["run_id"] not in ex["bad_runs"]]


def rtt_samples(ex, cond):
    ok = {b["block"] for b in ex["blocks"] if b["condition"] == cond and b["valid"]}
    return [r["rtt_ms"] for r in ex["rtt"] if r["block"] in ok and not r["warmup"]]


def transfer(execs, bucket):
    """Fit the threshold on all other executions, score on each held-out execution."""
    k = n = 0
    per = []
    for i, ex in enumerate(execs):
        train = [r for j, o in enumerate(execs) if j != i for r in rows_of(o, bucket)]
        test = rows_of(ex, bucket)
        t, sign = te.best_threshold([r[1] for r in train], [r[2] for r in train])
        hit = sum(int((x < t) if sign == 1 else (x >= t)) == y for _, x, y in test)
        per.append({"execution": ex["res"]["execution_id"], "n": len(test), "accuracy": round(hit / len(test), 3), "threshold_ms": round(t, 2), "faster_means_refused": sign == 1})
        k, n = k + hit, n + len(test)
    return {"pooled_accuracy": round(k / n, 3), "n": n, "ci95": te.wilson(k, n), "per_heldout_execution": per}


def verdict(ps, n_exec):
    alpha = 0.05 / (n_exec * 3)
    if min(ps) < alpha:
        return "leak detected"
    if all(p < 0.05 for p in ps):
        return "leak likely (nominally significant in every execution)"
    if any(p < 0.05 for p in ps):
        return "unstable (nominally significant in some executions only)"
    return "no leak detected (inconclusive as to absence)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    execs = [load_exec(d) for d in a.dirs]
    n_exec = len(execs)
    out = {"executions": [], "bonferroni_alpha": round(0.05 / (n_exec * 3), 5), "n_executions_complete": sum(e["res"]["status"] == "COMPLETE" for e in execs),
           "chance_ci95_one_execution_n200": te.wilson(100, 200), "buckets": {}, "rtt": {}}
    for ex in execs:
        r = ex["res"]
        out["executions"].append({"execution_id": r["execution_id"], "seed": r["seed"], "status": r["status"], "started_utc": r["started_utc"],
                                  "wall_clock_s": r["wall_clock_s"], "code_tree_sha256": r["code_revision"]["tree_sha256"],
                                  "unusable_runs": len(r.get("unusable", [])), "unusable_rtt_blocks": len(r.get("unusable_rtt_blocks", []))})
    for b in te.BUCKETS:
        c = [ex["res"]["conditions"][str(b)] for ex in execs]
        k = sum(round(x["heldout_accuracy"] * x["total_requests"]) for x in c)
        n = sum(x["total_requests"] for x in c)
        out["buckets"][str(b)] = {
            "n_per_execution": [x["total_requests"] for x in c], "class_counts_per_execution": [[x["n_refused"], x["n_answered"]] for x in c],
            "majority_baseline": [x["majority_baseline"] for x in c], "heldout_accuracy": [x["heldout_accuracy"] for x in c],
            "heldout_accuracy_ci95": [x["heldout_accuracy_ci95"] for x in c], "auc_refused_faster": [x["auc_refused_faster"] for x in c],
            "permutation_p": [x["permutation_p"] for x in c], "added_median_latency_for_answered_ms": [x["added_median_latency_for_answered_requests_ms"] for x in c],
            "run_wall_clock_median_s": [round(x["run_wall_clock_s"]["median_ms"] / 1000, 2) for x in c],
            "pooled_heldout": {"accuracy": round(k / n, 3), "n": n, "ci95": te.wilson(k, n)},
            "leave_one_execution_out": transfer(execs, b),
            "verdict": "control: leak detected" if b == 0 and verdict([x["permutation_p"] for x in c], n_exec) == "leak detected" else verdict([x["permutation_p"] for x in c], n_exec)}
    for cond in CONDS:
        per = []
        for ex in execs:
            r = ex["res"]["broker_mailbox_rtt"].get(cond)
            v = rtt_samples(ex, cond)
            if not v:
                continue
            p = te.pcts(v)
            entry = {"n": p["n"], "median_ms": p["median_ms"], "p95_ms": p["p95_ms"], "p99_ms": p["p99_ms"], "max_ms": p["max_ms"], "blocks": r["blocks"] if r else 0}
            if r and "increase_vs_idle" in r:
                entry["increase_vs_idle"] = r["increase_vs_idle"]
            per.append(entry)
        out["rtt"][cond] = {"per_execution": per}
        if per:
            out["rtt"][cond]["median_ms_range"] = [min(e["median_ms"] for e in per), max(e["median_ms"] for e in per)]
            out["rtt"][cond]["p99_ms_range"] = [min(e["p99_ms"] for e in per), max(e["p99_ms"] for e in per)]
            if all("increase_vs_idle" in e for e in per):
                out["rtt"][cond]["median_increase_pct_range"] = [min(e["increase_vs_idle"]["median_pct"] for e in per), max(e["increase_vs_idle"]["median_pct"] for e in per)]
                out["rtt"][cond]["p99_increase_pct_range"] = [min(e["increase_vs_idle"]["p99_pct"] for e in per), max(e["increase_vs_idle"]["p99_pct"] for e in per)]
    Path(a.out).write_text(json.dumps(out, indent=1, sort_keys=True))
    print(json.dumps({"buckets": {b: {k: v[k] for k in ("heldout_accuracy", "permutation_p", "verdict")} | {"pooled": v["pooled_heldout"], "loeo": v["leave_one_execution_out"]["pooled_accuracy"]} for b, v in out["buckets"].items()},
                      "rtt_median_inc": {c: v.get("median_increase_pct_range") for c, v in out["rtt"].items()}}, indent=1))


if __name__ == "__main__":
    main()
