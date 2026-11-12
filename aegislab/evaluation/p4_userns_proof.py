"""Finale P4, task 2 (F4) proof: no container runs as the host UID that owns the signing key.

    AEGIS_VAR=<fresh scratch> python evaluation/p4_userns_proof.py --out-dir <new dir> [--models <_models dir>]

What it records, all from the live system (nothing is inferred from configuration):

  1. A real lab run (stub model, the scripted red agent) through runs.start. While it runs, every container labelled
     aegislab=1 is sampled: `podman top <name> user huser pid hpid` (the process table as ps shows it, inside and on the host),
     /proc/<host pid>/status Uid and /proc/<host pid>/uid_map. Expected: every container process runs as container UID 900
     and a host UID that is neither the broker's (this process's) nor any other container's.
  2. The sandboxed model server (scripts/start_model_server.sh --sandbox), if the model files are present, started BEFORE the
     lab run and running during it: the same sample, plus the owner of its UNIX socket and launch.json's
     server_process_host_uid. Distinct host UIDs are checked among containers that run at the same time (podman reuses a
     range after its container exits).
  3. Key files: owner and mode of var/keys/*.pem and tokens.json and of the model API key file (0600, owned by the broker).
  4. Negative controls, in this order:
       a. runtime.launch with the key directory as a mount source: refused by runtime._check_mounts before podman runs;
       b. raw `podman run` with the hardening flags (--userns auto, --user 900:900) and the scratch key directory bind-mounted
          read-only: reading the evidence key must fail with "Permission denied" (errno 13), because the mapped host UID
          is not the key's owner and the file is 0600.
     Only the scratch AEGIS_VAR's keys are ever mounted, never the operator's real var/keys.
Outputs: result.json (checks, classification) and observations.jsonl (every sample).
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
from aegis import runs, runtime, store, userns  # noqa: E402
from llm_common import sha256_file  # noqa: E402
from revision import code_revision  # noqa: E402

SOURCES = ["aegis/runtime.py", "aegis/userns.py", "aegis/runs.py", "aegis/model_client.py", "scripts/start_model_server.sh",
           "Containerfile", "evaluation/p4_userns_proof.py"]


def sh(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def sample(name):
    """podman top + /proc for one container; None if it is gone."""
    top = sh(["podman", "top", name, "user", "huser", "pid", "hpid", "args"])
    pid = sh(["podman", "inspect", name, "--format", "{{.State.Pid}}"]).stdout.strip()
    if top.returncode or not pid.isdigit() or pid == "0":
        return None
    try:
        status = Path("/proc/%s/status" % pid).read_text()
        uid_line = next(ln for ln in status.splitlines() if ln.startswith("Uid:")).split()[1:]
        uid_map = Path("/proc/%s/uid_map" % pid).read_text().split()
    except (OSError, StopIteration):
        return None
    procs = []
    for ln in top.stdout.splitlines()[1:]:
        f = ln.split(None, 4)
        if len(f) >= 4:
            procs.append({"user": f[0], "huser": f[1], "pid": f[2], "hpid": f[3], "args": (f[4] if len(f) > 4 else "")[:60]})
    return {"name": name, "host_pid": int(pid), "proc_status_uid": [int(x) for x in uid_line], "proc_uid_map": uid_map,
            "podman_top": procs, "idmappings": userns.container_maps(name)}


def live_names(label="aegislab=1"):
    return [n for n in sh(["podman", "ps", "--filter", "label=" + label, "--format", "{{.Names}}"]).stdout.split() if n]


def check_proc(s, me):
    hosts = {s["proc_status_uid"][0]} | {int(p["huser"]) for p in s["podman_top"] if p["huser"].isdigit()}
    inner = {p["user"] for p in s["podman_top"]}
    return {"host_uids": sorted(hosts), "container_users": sorted(inner),
            "ok": me not in hosts and all(u.isdigit() is False or u == str(userns.SANDBOX_UID) for u in inner)
            and all(p["huser"].isdigit() for p in s["podman_top"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--models", default=str(ROOT.parent.parent.parent.parent / "_models"))
    a = ap.parse_args()
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=False)
    me = os.getuid()
    obs, checks = [], {}
    t0 = time.time()

    # 2 (started first, so that it runs concurrently with the lab run's containers). podman --userns auto reuses a range once
    # its container has exited, so distinctness is a property of containers that run AT THE SAME TIME; it is checked that way.
    models = Path(a.models)
    mrun = launch = None
    if (models / "qwen2.5-0.5b-instruct-q4_k_m.gguf").exists():
        p = sh(["bash", str(ROOT / "scripts/start_model_server.sh"), "--sandbox"], timeout=240)
        if p.returncode == 0:
            mrun = Path(p.stdout.strip().splitlines()[-1])
            launch = json.loads((mrun / "launch.json").read_text())
        else:
            obs.append({"kind": "model_server", "error": p.stderr[-300:]})
            checks["model_server_started"] = False
    else:
        obs.append({"kind": "model_server", "skipped": "model files not present"})

    # 1. a real lab run, sampled while it runs
    rid = "P4U-RUN"
    runs.create_run(rid, timing_bucket_ms=250)
    runs.freeze(rid)
    th = threading.Thread(target=runs.start, args=(rid,), kwargs={"wait": True})
    th.start()
    seen = {}
    while th.is_alive():
        for n in live_names():
            if launch and n == launch["container"]:
                continue
            if n not in seen or len(seen[n]["podman_top"]) == 0:
                s = sample(n)
                if s:
                    seen[n] = s
        time.sleep(0.05)
    th.join()
    msample = sample(launch["container"]) if launch else None  # still running
    run = runs.Run(rid)
    tenant = []
    for n, s in sorted(seen.items()):
        c = check_proc(s, me)
        obs.append({"kind": "lab_container", **s, **c})
        tenant.append((n, c))
    roles = {n.rsplit("-", 1)[-1] for n, _ in tenant}
    host_uids = [c["host_uids"][0] for _, c in tenant]
    checks["lab_run_sealed"] = run.state == "SEALED"
    checks["lab_containers_sampled_red_blue_model"] = {"red", "blue", "model"} <= roles
    checks["lab_every_container_process_runs_as_container_uid_900"] = all(c["ok"] for _, c in tenant) and bool(tenant)
    checks["lab_no_container_host_uid_equals_the_broker_uid"] = all(me not in c["host_uids"] for _, c in tenant)
    checks["lab_container_host_uids_distinct"] = len(set(host_uids)) == len(host_uids)
    ranges = userns.subid_ranges()
    checks["lab_container_host_uids_in_the_subordinate_range"] = all(any(f <= u < f + n for f, n in ranges) for u in host_uids)

    if launch:
        s = msample
        sock = os.lstat(mrun / "sock/llama.sock")
        key = os.stat(mrun / "key")
        c = check_proc(s, me) if s else {"ok": False, "host_uids": []}
        obs.append({"kind": "model_server", **(s or {}), **c, "socket_owner_uid": sock.st_uid,
                    "launch_server_process_host_uid": launch.get("server_process_host_uid"), "api_key_file_owner": key.st_uid,
                    "api_key_file_mode": oct(key.st_mode & 0o777), "userns": launch.get("userns")})
        checks["model_server_runs_as_container_uid_900_not_the_broker"] = bool(s) and c["ok"]
        checks["model_server_host_uid_matches_launch_record_and_socket_owner"] = bool(s) and (
            c["host_uids"] == [launch["server_process_host_uid"]] == [sock.st_uid])
        checks["model_server_host_uid_differs_from_the_concurrent_lab_containers"] = bool(s) and not set(c["host_uids"]) & set(host_uids)
        checks["model_api_key_file_is_broker_owned_0600"] = key.st_uid == me and (key.st_mode & 0o777) == 0o600
        sh(["bash", str(ROOT / "scripts/start_model_server.sh"), "--stop", str(mrun)])

    # 3. key files
    keys = sorted(store.p("keys").iterdir())
    kinfo = [{"file": k.name, "owner": k.stat().st_uid, "mode": oct(k.stat().st_mode & 0o777)} for k in keys if k.is_file()]
    obs.append({"kind": "key_files", "files": kinfo, "broker_uid": me})
    checks["key_files_broker_owned_and_private"] = bool(kinfo) and all(k["owner"] == me and k["mode"] in ("0o600", "0o400") for k in kinfo)

    # 4a. the guard
    try:
        runtime.launch("aegis-p4-negative-guard", "red", [(str(store.p("keys")), "/aegis/keys", "ro")], {})
        guard = "launched (BUG)"
        runtime.stop("aegis-p4-negative-guard")
    except runtime.RuntimeFailure as exc:
        guard = "refused: %s" % str(exc)[:120]
    obs.append({"kind": "negative_control_guard", "result": guard})
    checks["guard_refuses_key_directory_mount"] = guard.startswith("refused")
    # 4b. raw podman, the same flags, scratch key directory bind-mounted read-only
    raw = sh(["podman", "run", "--rm", "--network", "none", "--userns", "auto:size=%d" % userns.USERNS_SIZE,
              "--user", "%d:%d" % (userns.SANDBOX_UID, userns.SANDBOX_UID), "-v", "%s:/k:ro,Z" % store.p("keys"),
              runtime.IMAGE, "python", "-c",
              "import os,sys\ntry:\n open('/k/broker_ed25519.pem').read(); print('READ')\nexcept OSError as e:\n print('errno', e.errno)\nprint(os.getuid())"],
             timeout=120)
    lines = raw.stdout.split()
    obs.append({"kind": "negative_control_raw_mount", "stdout": raw.stdout.strip(), "stderr": raw.stderr.strip()[-200:], "exit": raw.returncode})
    checks["raw_mount_of_the_evidence_key_is_unreadable_errno_13"] = lines[:2] == ["errno", "13"] and "READ" not in lines

    res = {"schema": "aegislab-p4-userns-proof/1", "started_utc": datetime.fromtimestamp(t0, timezone.utc).isoformat(),
           "wall_clock_s": round(time.time() - t0, 1), "broker_uid": me, "subuid_ranges": ranges,
           "image": runtime.IMAGE, "image_id": runtime.image_id(), "hardening_flags": runtime.hardening_flags("red"),
           "code_revision": code_revision(), "source_sha256": {k: sha256_file(ROOT / k) for k in SOURCES},
           "checks": checks, "classification": "pass" if all(checks.values()) else "fail"}
    with (out / "observations.jsonl").open("w") as f:
        for o in obs:
            f.write(json.dumps(o, sort_keys=True) + "\n")
    res["observations_sha256"] = sha256_file(out / "observations.jsonl")
    res["observation_count"] = len(obs)
    (out / "result.json").write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    for k, v in checks.items():
        print("%-4s %s" % ("ok" if v else "FAIL", k))
    print("classification:", res["classification"])
    return 0 if res["classification"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
