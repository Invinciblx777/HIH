"""Finale P3: ONE execution of the timing classifier with the REAL model (closes the gap stated in THREAT_MODEL row 5:
"a real model's variable latency can cross the bucket boundaries; not measured").

    AEGIS_VAR=<fresh scratch> python evaluation/timing_real_model.py --seed 20261110 --out-dir <new dir> [--runs 20] [--calib-runs 8]

Same procedure and analysis as the stub executions (timing_closeout.classification / timing_eval.analyse, both unchanged and
reused here), with these differences, all fixed before any classification run:
  * the model is the real one: scripts/start_model_server.sh --sandbox (Qwen2.5-0.5B Q4_K_M, llama.cpp CPU, rootless Podman
    --network none, UNIX socket), AEGIS_MODEL_MAX_TOKENS=96 (the console default), temperature 0;
  * phase 1 (calibration, not used by the classifier): --calib-runs unpadded runs measure the latency distribution red sees;
    the third padding setting is then ceil(p99 of the answered requests / 100 ms) * 100 ms, written to the result BEFORE
    phase 2 starts;
  * phase 2 (classification): settings 0 ms (unpadded), 250 ms (the shipped default) and the p99 bucket, --runs runs each,
    interleaved in a seeded random order; 10 attacks per run (samples/attack_pack.json with the sample defence; with the real
    model 3 are refused and 7 answered, counted from the raw file into classes_per_run_observed), grouped 5-fold held-out
    accuracy, 1000-shuffle permutation test;
  * no broker-RTT contention part (that one measures the mailbox, not the model, and is unchanged).
Raw files: raw_calibration.jsonl, raw_runs.json, raw_classification.jsonl; result.json records their sha256.
"""
import argparse
import json
import math
import os
import random
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
import timing_closeout as tc  # noqa: E402
import timing_eval as te  # noqa: E402
from aegis import model_client as mc, runtime, store  # noqa: E402
from revision import code_revision  # noqa: E402


def start_model(models):
    env = dict(os.environ, AEGIS_MODELS_DIR=str(models))
    p = subprocess.run(["bash", str(ROOT / "scripts/start_model_server.sh"), "--sandbox", "--threads", "6",
                        "--expect-model-sha256", "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
                        "--expect-server-sha256", "17d2573dede0314fe681f3c2c821a9a44818949e1073200292353efb21c426bb"],
                       capture_output=True, text=True, env=env, timeout=240)
    if p.returncode:
        raise RuntimeError("model server did not start: " + p.stderr[-400:])
    run = Path(p.stdout.strip().splitlines()[-1])
    for line in (run / "model.env").read_text().splitlines():
        k, v = line.split("=", 1)
        os.environ[k] = v.strip("'")
    os.environ["AEGIS_MODEL_MAX_TOKENS"] = "96"
    mc.OpenAICompatibleClient(mc.load_config()).ping()
    return run


def calibration(n, out):
    raw = []
    for i in range(n):
        rid = "TR-CAL-%02d" % (i + 1)
        run, wall = te.do_run(rid, 0)
        obs = store.read_json(run.dir / "sealed/red_observed.json", [])
        for k, o in enumerate(obs):
            raw.append({"run_id": rid, "seq": k, "attack_id": o["attack_id"], "latency_ms": o["latency_ms"], "refused": int(bool(o["refused"])),
                        "state": run.state, "complete": run.record.get("complete")})
        print("  calibration %s wall=%.1f s state=%s n=%d" % (rid, wall, run.state, len(obs)), flush=True)
    with (out / "raw_calibration.jsonl").open("w") as f:
        for r in raw:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    ans = [r["latency_ms"] for r in raw if not r["refused"]]
    ref = [r["latency_ms"] for r in raw if r["refused"]]
    p = te.pcts(ans)
    bucket = int(math.ceil(p["p99_ms"] / 100.0) * 100)
    return {"runs": n, "requests": len(raw), "answered": te.pcts(ans), "refused": te.pcts(ref) if ref else None,
            "answered_min_ms": round(min(ans), 2), "answered_max_ms": round(max(ans), 2),
            "bucket_rule": "ceil(p99 of answered / 100 ms) * 100 ms", "p99_bucket_ms": bucket}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--calib-runs", type=int, default=8)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--models-dir", default=str(ROOT.parent.parent.parent.parent / "_models"))
    a = ap.parse_args()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=False)
    exec_id = "TR-%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(3))
    t0 = time.time()
    res = {"execution_id": exec_id, "argv": sys.argv, "started_utc": datetime.fromtimestamp(t0, timezone.utc).isoformat(), "seed": a.seed,
           "status": "RUNNING", "label": "ONE execution, real model (not three like the stub timing evidence)",
           "config": {"runs_per_setting": a.runs, "calibration_runs": a.calib_runs, "attacks_per_run": 10,
                      "aegis_var": os.environ.get("AEGIS_VAR")},
           "rules": dict(tc.RULES, verdict_rule="a padded setting is 'leak detected' if its permutation p < 0.05/2 (Bonferroni over the 2 padded "
                                                "settings of this one execution); otherwise 'no leak detected (inconclusive as to absence)'"),
           "code_revision": code_revision(), "source_sha256": tc.source_hashes(), "host": tc.host_snapshot()}
    (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))
    mrun = None
    try:
        mrun = start_model(Path(a.models_dir))
        res["model"] = {k: v for k, v in mc.load_config().describe().items() if k not in ("unix_socket",)}
        res["sandbox_image_id"] = runtime.image_id()
        res["environment"] = runtime.environment()
        print("phase 1: calibration", flush=True)
        res["calibration"] = calibration(a.calib_runs, out)
        b = res["calibration"]["p99_bucket_ms"]
        res["padding_intervals_ms"] = [0, 250, b]
        (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))  # the p99 bucket is on disk before phase 2
        print("phase 2: buckets %s" % res["padding_intervals_ms"], flush=True)
        te.BUCKETS = (0, 250, b)   # timing_closeout.classification iterates te.BUCKETS; the module file is not modified
        res["conditions"], res["unusable"] = tc.classification(a, out, exec_id)
        raw = [json.loads(x) for x in (out / "raw_classification.jsonl").read_text().splitlines() if x.strip()]
        per_run = {}
        for r in raw:
            per_run.setdefault((r["bucket_ms"], r["run_id"]), [0, 0])[int(bool(r["refused"]))] += 1
        res["classes_per_run_observed"] = [{"answered": x[0], "refused": x[1], "runs": sum(tuple(v) == x for v in per_run.values())}
                                           for x in sorted({tuple(v) for v in per_run.values()})]
        alpha = 0.05 / 2
        res["verdicts"] = {k: ("leak detected" if c["permutation_p"] < alpha else "no leak detected (inconclusive as to absence)")
                           for k, c in res["conditions"].items() if k != "0"}
        res["status"] = "COMPLETE"
    except BaseException as exc:
        res["status"] = "FAILED"
        res["failure"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
        raise
    finally:
        if mrun:
            subprocess.run(["bash", str(ROOT / "scripts/start_model_server.sh"), "--stop", str(mrun)], capture_output=True, timeout=60)
        res["host"]["loadavg_after"] = os.getloadavg()
        res["finished_utc"] = datetime.now(timezone.utc).isoformat()
        res["wall_clock_s"] = round(time.time() - t0, 1)
        res["raw_files_sha256"] = {n: tc.sha(out / n) for n in ("raw_calibration.jsonl", "raw_runs.json", "raw_classification.jsonl") if (out / n).exists()}
        res["confounders"] = [
            "ONE execution on one host; the stub timing evidence has three",
            "label (refused) is determined by attack id: 10 distinct payloads per run (classes_per_run_observed); at temperature 0 each "
            "answered payload gets the same answer every time, so its latency is mostly a property of the payload",
            "refused requests are blocked by the input rules before the model, so they are fast; answered ones wait for the model",
            "the p99 bucket is sized from this host's calibration runs; another CPU, model or max_tokens needs its own",
            "single host, laptop CPU, desktop session running, SELinux enforcing, rootless Podman",
            "a single-threshold classifier is a weak adversary",
        ]
        (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))
    print("status", res["status"], "wall", res["wall_clock_s"], "s")


if __name__ == "__main__":
    main()
