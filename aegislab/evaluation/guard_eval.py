"""Finale P16 (part A5): detection and false positives of the blue-team guard modes, regex vs qwen3guard vs both.

    .venv/bin/python evaluation/guard_eval.py --guard-rundir RUN --datasets DIR --out evidence/finale_p16_2026-11-20/guard_eval

Inputs (downloaded once, outside the repo, at the pinned revisions below; DIR/SHA256SUMS lists their hashes):
  attacks  Lakera/gandalf_ignore_instructions, test split, all 112 rows (DIR/gandalf/test.json, from the parquet file)
           JailbreakBench/JBB-Behaviors harmful-behaviors.csv, all 100 goals
  benign   Anthropic/hh-rlhf helpful-base test: the first human turn of a seeded sample of 200 dialogues
           JailbreakBench/JBB-Behaviors benign-behaviors.csv, all 100 goals (benign topics phrased like the harmful ones: a hard
           false-positive set, reported on its own)
           samples/attack_pack.json's benign items are not used: the tag's pack is attack-only
Prompt moderation only (the input text a red tenant would send), each text through:
  regex       samples/defence_config.json input_patterns (the tag's default blue config), applied as the defence runner does
  qwen3guard  the sandboxed Qwen3Guard-Gen-0.6B server (scripts/start_guard_server.sh), through guard/guard_runner.judge with
              its defaults (Controversial blocks, 1500 ms budget, 4000 characters; an error or timeout blocks and is counted)
  both        regex OR qwen3guard
Reported per set and pooled: TPR (attacks blocked), FPR (benign blocked), guard latency p50/p95 (wall time of one judge() call:
slot reset + moderation), guard errors. Written: result.json (figures, dataset ids/revisions/hashes, seed, environment) and
verdicts.jsonl (one row per text: set, row index, sha256 of the text, regex verdict, guard safety/categories/ms/error). The texts
themselves are not copied into the evidence; they are reproducible from the pinned revision and the row index.
"""
import argparse
import csv
import gzip
import hashlib
import json
import os
import random
import re
import statistics
import sys
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluation"))
from revision import code_revision  # noqa: E402

SEED = 20261120
DATASETS = {
    "gandalf": {"id": "Lakera/gandalf_ignore_instructions", "revision": "04737b65e90a6794ec227012e4a255a7def6344b",
                "file": "data/test-00000-of-00001-bc92128b9288a6d1.parquet", "local": "gandalf/test.json", "kind": "attack"},
    "jbb_harmful": {"id": "JailbreakBench/JBB-Behaviors", "revision": "886acc352a31533ffbcf4ef22c744658688086fc",
                    "file": "data/harmful-behaviors.csv", "local": "jbb/harmful-behaviors.csv", "kind": "attack"},
    "hh_helpful": {"id": "Anthropic/hh-rlhf", "revision": "09be8c5bbc57cb3887f3a9732ad6aa7ec602a1fa",
                   "file": "helpful-base/test.jsonl.gz", "local": "hh/helpful-base-test.jsonl.gz", "kind": "benign", "sample": 200},
    "jbb_benign": {"id": "JailbreakBench/JBB-Behaviors", "revision": "886acc352a31533ffbcf4ef22c744658688086fc",
                   "file": "data/benign-behaviors.csv", "local": "jbb/benign-behaviors.csv", "kind": "benign"},
}


def load_guard_runner():
    """guard/guard_runner.py without a frozen config (its judge() takes the settings explicitly)."""
    sys.modules.setdefault("spool", types.ModuleType("spool"))
    dr = types.ModuleType("defence_runner")
    dr.CFG = {}
    sys.modules["defence_runner"] = dr
    sys.path.insert(0, str(ROOT / "guard"))
    import guard_runner
    return guard_runner


def load_texts(ddir: Path):
    out = []
    for name, d in DATASETS.items():
        p = ddir / d["local"]
        if name == "gandalf":
            rows = [(i, r["text"]) for i, r in enumerate(json.loads(p.read_text()))]
        elif name.startswith("jbb"):
            with open(p, newline="") as f:
                rows = [(int(r["Index"]), r["Goal"]) for r in csv.DictReader(f)]
        else:
            lines = gzip.open(p, "rt").read().splitlines()
            idx = sorted(random.Random(SEED).sample(range(len(lines)), d["sample"]))
            rows = []
            for i in idx:
                chosen = json.loads(lines[i])["chosen"]
                m = re.search(r"Human:(.*?)(\n\nAssistant:|$)", chosen, re.S)
                rows.append((i, m.group(1).strip()))
        out += [{"set": name, "kind": d["kind"], "row": i, "text": t} for i, t in rows]
    return out


def pct(xs, q):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))], 1) if xs else None


def rates(rows, key):
    a = [r for r in rows if r["kind"] == "attack"]
    b = [r for r in rows if r["kind"] == "benign"]
    return {"tpr": round(sum(r[key] for r in a) / len(a), 4) if a else None, "n_attack": len(a),
            "blocked_attack": sum(r[key] for r in a),
            "fpr": round(sum(r[key] for r in b) / len(b), 4) if b else None, "n_benign": len(b),
            "blocked_benign": sum(r[key] for r in b)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guard-rundir", required=True)
    ap.add_argument("--datasets", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    gr = load_guard_runner()
    gdir = Path(a.guard_rundir)
    # the host reaches the guard's socket through its run directory (key at RUN/key, socket at RUN/sock/guard.sock): the same
    # server and request path as the defence runner's mount, without a container hop
    gr.GUARD_DIR = str(gdir)
    settings = gr.guard_settings({"guard_mode": "qwen3guard"})
    cfg = json.loads((ROOT / "samples/defence_config.json").read_text())
    pats = [re.compile(p, re.I) for p in cfg["input_patterns"]]
    texts = load_texts(Path(a.datasets))
    gr.warm_up(str(gdir))
    rows = []
    t_start = time.time()
    for t in texts:
        regex = any(p.search(t["text"]) for p in pats)
        g = gr.judge(t["text"], settings)
        rows.append({"set": t["set"], "kind": t["kind"], "row": t["row"],
                     "text_sha256": hashlib.sha256(t["text"].encode()).hexdigest(), "chars": len(t["text"]),
                     "regex": regex, "qwen3guard": g["block"], "both": regex or g["block"],
                     "guard": {k: v for k, v in g.items() if k != "block"}})
    wall = time.time() - t_start
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "verdicts.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    ms = [r["guard"]["ms"] for r in rows if not r["guard"].get("error")]
    per_set = {s: {m: rates([r for r in rows if r["set"] == s], m) for m in ("regex", "qwen3guard", "both")} for s in DATASETS}
    pooled = {m: rates(rows, m) for m in ("regex", "qwen3guard", "both")}
    launch = json.loads((gdir / "launch.json").read_text())
    res = {"experiment": "p16_guard_eval", "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seed": SEED,
           "datasets": {k: {x: v[x] for x in ("id", "revision", "file", "kind")} | ({"sample": v["sample"]} if "sample" in v else {})
                        for k, v in DATASETS.items()},
           "dataset_file_sha256": dict(ln.split("  ", 1)[::-1] for ln in (Path(a.datasets) / "SHA256SUMS").read_text().splitlines() if ln),
           "regex_patterns": cfg["input_patterns"], "regex_source": "samples/defence_config.json (sha256 %s)" % hashlib.sha256((ROOT / "samples/defence_config.json").read_bytes()).hexdigest(),
           "guard": {"model_file": launch["model_file"], "model_sha256": launch["model_sha256"], "inference_server": launch["inference_server"],
                     "isolation": "rootless podman, network none, userns auto, uid %d" % launch["server_process_host_uid"],
                     "settings": {"block_controversial": settings["block_controversial"], "timeout_ms": int(settings["timeout_s"] * 1000),
                                  "max_chars": settings["max_chars"]}, "moderation": "prompt (input) only"},
           "n_texts": len(rows), "wall_s": round(wall, 1),
           "per_set": per_set, "pooled": pooled,
           "pooled_attack_vs_hh_benign": {m: rates([r for r in rows if r["set"] != "jbb_benign"], m) for m in ("regex", "qwen3guard", "both")},
           "guard_latency_ms": {"p50": pct(ms, 0.5), "p95": pct(ms, 0.95), "max": max(ms) if ms else None, "n": len(ms),
                                "mean": round(statistics.mean(ms), 1) if ms else None},
           "guard_errors": sum(1 for r in rows if r["guard"].get("error")),
           "guard_error_kinds": sorted({r["guard"]["error"] for r in rows if r["guard"].get("error")}),
           "safety_counts": {s: sum(1 for r in rows if r["guard"].get("safety") == s) for s in ("Safe", "Controversial", "Unsafe")},
           "code_revision": code_revision(),
           "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in
                             ("guard/guard_runner.py", "evaluation/guard_eval.py", "scripts/start_guard_server.sh", "samples/defence_config.json")},
           "host": {"cpu": os.popen("lscpu | sed -n 's/Model name: *//p'").read().strip(), "cpus": os.cpu_count()}}
    (out / "result.json").write_text(json.dumps(res, indent=1, sort_keys=True))
    print(json.dumps({"pooled": pooled, "latency": res["guard_latency_ms"], "errors": res["guard_errors"], "wall_s": res["wall_s"]}, indent=1))


if __name__ == "__main__":
    main()
