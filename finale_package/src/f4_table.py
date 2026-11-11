"""Print the F4 proof table from the raw observations of one evaluation/p4_userns_proof.py run (read only).

    python f4_table.py RESULT_DIR

One row per sampled container: name, user inside the container, host UID (podman top huser and /proc/<pid>/status),
uid_map; then the broker's UID and the two negative controls, verbatim from observations.jsonl.
"""
import json
import sys
from pathlib import Path

d = Path(sys.argv[1])
obs = [json.loads(x) for x in (d / "observations.jsonl").read_text().splitlines() if x.strip()]
res = json.loads((d / "result.json").read_text())
print("F4 proof: who runs each container (from podman top and /proc on the host)")
print("  %-28s %-10s %-24s %s" % ("container", "inside", "host UID (top / proc)", "uid_map"))
for o in obs:
    if o["kind"] in ("lab_container", "model_server"):
        top = ",".join(sorted({p["huser"] for p in o["podman_top"]}))
        name = o["name"] if o["kind"] == "lab_container" else "sandboxed model server"
        print("  %-28s %-10s %-24s %s" % (name[:28], ",".join(o["container_users"]), "%s / %s" % (top, o["proc_status_uid"][0]), " ".join(o["proc_uid_map"])))
print("  broker (owns the signing key): host UID %d" % res["broker_uid"])
g = next(o for o in obs if o["kind"] == "negative_control_guard")
r = next(o for o in obs if o["kind"] == "negative_control_raw_mount")
print("  guard, key directory as a mount source: %s" % g["result"][:90])
print("  raw podman run, key bind-mounted read-only: %s" % r["stdout"].strip().replace("\n", " ")[:90])
print("checks: %d/%d hold · classification: %s" % (sum(res["checks"].values()), len(res["checks"]), res["classification"]))
