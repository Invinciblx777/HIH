"""Create, freeze, execute, seal and release a run from the command line.

    python scripts/demo_run.py DEMO-001 [--no-release]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import evidence, runtime, runs, store  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--no-release", action="store_true")
    ap.add_argument("--bucket-ms", type=int, default=250)
    ap.add_argument("--tag", action="append", default=[])
    a = ap.parse_args()
    print("image:", runtime.build_image(store.ROOT))
    runs.create_run(a.run_id, timing_bucket_ms=a.bucket_ms, tags=a.tag or ["demo"])
    runs.freeze(a.run_id)
    runs.start(a.run_id, wait=True)
    print("state:", runs.Run(a.run_id).state)
    if not a.no_release:
        res = runs.release(a.run_id)
        print("release:", json.dumps(res["verification"]["ok"]), res["commitments"])
        rep = evidence.build(a.run_id)
        print(json.dumps({k: rep[k] for k in ("outcome_summary", "canary", "commitments")}, indent=1))
        print(json.dumps(rep["access_control"], indent=1))


if __name__ == "__main__":
    main()
