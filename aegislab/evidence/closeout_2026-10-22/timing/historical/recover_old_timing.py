"""Rebuild per-request observations of the two SAVED 22 Oct executions from their surviving scratch state and
re-run the analysis with the recorded seed. Read-only on the source state; writes only under the output dir."""
import json, sys, hashlib
from pathlib import Path
sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[1] + "/evaluation")
import timing_eval as te
VAR = Path(sys.argv[2]); OUT = Path(sys.argv[3]); OUT.mkdir(parents=True, exist_ok=True)
SAVED = Path(sys.argv[4])
for var, saved, seed in (("timing", "timing.json", 7), ("timing2", "timing_execution_2.json", 11)):
    ref = json.loads((SAVED / saved).read_text())
    raw, res = [], {}
    for b in te.BUCKETS:
        rows = []
        for i in range(20):
            rid = "TIM-B%d-%02d" % (b, i + 1)
            p = VAR / var / "runs" / rid / "sealed" / "red_observed.json"
            for k, o in enumerate(json.loads(p.read_text())):
                rows.append((i, o["latency_ms"], int(bool(o["refused"]))))
                raw.append({"run_id": rid, "bucket_ms": b, "rep": i, "seq": k, "attack_id": o["attack_id"], "latency_ms": o["latency_ms"], "refused": int(bool(o["refused"]))})
        c = te.analyse(rows, seed)
        want = ref["conditions"][str(b)]
        same = all(c[k] == want[k] for k in ("heldout_accuracy", "heldout_accuracy_ci95", "auc_refused_faster", "permutation_p", "majority_baseline", "n_refused", "n_answered"))
        res[str(b)] = {"recomputed_accuracy": c["heldout_accuracy"], "saved_accuracy": want["heldout_accuracy"], "recomputed_p": c["permutation_p"], "saved_p": want["permutation_p"], "all_fields_identical": same}
        print(saved, b, res[str(b)], flush=True)
    f = OUT / (saved.replace(".json", "") + "_recovered_raw.jsonl")
    f.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in raw))
    (OUT / (saved.replace(".json", "") + "_reproduction.json")).write_text(json.dumps({"saved_file": saved, "seed": seed, "source_state": "var/validation_2026-10-22/" + var, "raw_sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "per_bucket": res}, indent=1))
