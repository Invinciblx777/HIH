"""Create, freeze, execute, seal and release a run from the command line.

    python scripts/demo_run.py DEMO-001 [--no-release] [--bundle-dir DIR]

Exit status is 0 only if the run reached RELEASED (or SEALED with --no-release) and, when released, the
audit verifies against its terminal checkpoint. Refuses to touch an existing run id.
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
    ap.add_argument("--bundle-dir", help="export the reviewer evidence bundle here after release (must not exist yet)")
    a = ap.parse_args()
    print("state dir:", store.VAR)
    print("image:", runtime.build_image(store.ROOT))
    runs.create_run(a.run_id, timing_bucket_ms=a.bucket_ms, tags=a.tag or ["demo"])
    runs.freeze(a.run_id)
    runs.start(a.run_id, wait=True)
    state = runs.Run(a.run_id).state
    print("state:", state)
    if a.no_release:
        return 0 if state == "SEALED" else 1
    if state != "SEALED":
        print("run did not seal; not releasing", file=sys.stderr)
        return 1
    res = runs.release(a.run_id)
    v = res["verification"]
    print("release: state=%s audit_ok=%s terminal_verified=%s entries=%d commitments=%s" % (
        res["state"], v["ok"], v["terminal_verified"], v["entries"], res["commitments"]))
    rep = evidence.build(a.run_id)
    print(json.dumps({k: rep[k] for k in ("outcome_summary", "canary", "commitments")}, indent=1))
    print("denied access attempts recorded:", len(rep["access_control"]))
    if a.bundle_dir:
        print("bundle:", json.dumps(evidence.export_bundle(a.run_id, a.bundle_dir)))
    return 0 if (res["state"] == "RELEASED" and v["ok"] and v["terminal_verified"]) else 1


if __name__ == "__main__":
    sys.exit(main())
