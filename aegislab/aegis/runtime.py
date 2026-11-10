"""Container runtime wrapper (rootless Podman + crun in the prototype).

Every tenant workload runs from the same small image with:
  --network none        no network namespace interfaces except loopback
  --read-only           immutable root filesystem, tmpfs /tmp only
  --cap-drop ALL        no Linux capabilities
  no-new-privileges     setuid binaries cannot raise privileges
  --userns auto --user 900:900
                        (finale P4, F4; was --userns keep-id) every container gets its OWN range of the user's subordinate
                        UIDs and runs as non-root UID 900 inside it, so its host UID is neither the broker's (the owner of
                        the signing key and the model API key) nor another container's. The broker keeps owning every
                        mount source and grants that one host UID access with a POSIX ACL entry between `podman create`
                        and `podman start` (aegis/userns.py); the grant is removed again when the container is stopped
  pids/memory/cpu       cgroup v2 limits; per-tenant cpusets when the cpuset
                        controller is delegated (often not, for rootless)
  :Z volume labels      private SELinux MCS label per container (Fedora/RHEL)
The applied settings are read back with ``podman inspect`` and written to the
audit log, so the evidence reflects what the runtime reports, not the request.
"""
import json
import os
import platform
import shutil
import subprocess
import threading
from pathlib import Path

from . import userns

IMAGE = "localhost/aegislab-sandbox:0.1"
BASE_IMAGE = "docker.io/library/python:3.12-slim"

LIMITS = {
    "red": {"cpus": "1.0", "memory": "256m", "pids": "64", "cpuset": "2-3"},
    "blue": {"cpus": "1.0", "memory": "256m", "pids": "64", "cpuset": "4-5"},
    "model": {"cpus": "2.0", "memory": "512m", "pids": "64", "cpuset": "6-7"},
}
COMMANDS = {"red": "red_agent.py", "blue": "defence_runner.py", "model": "model_worker.py"}


class RuntimeFailure(RuntimeError):
    pass


def _run(args, check=True):
    out = subprocess.run(args, capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeFailure("%s: %s" % (args[1], (out.stderr or "").strip()[-300:]))
    return out


def cpuset_available() -> bool:
    """Rootless Podman can pin CPUs only if systemd delegates the cpuset controller."""
    import os
    uid = os.getuid()
    path = "/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/cgroup.controllers" % (uid, uid)
    try:
        return "cpuset" in open(path).read().split()
    except OSError:
        return False


def build_image(root: Path) -> str:
    _run(["podman", "build", "-q", "-t", IMAGE, "-f", str(Path(root) / "Containerfile"), str(root)])
    return image_id()


def image_id(image=IMAGE) -> str:
    return _run(["podman", "image", "inspect", image, "--format", "{{.Id}}"]).stdout.strip()


def image_repo_digest(image=BASE_IMAGE) -> str:
    return _run(["podman", "image", "inspect", image, "--format", "{{.Digest}}"]).stdout.strip()


def environment() -> dict:
    info = json.loads(_run(["podman", "info", "--format", "json"]).stdout)
    host = info.get("host", {})
    return {
        "podman": info.get("version", {}).get("Version"),
        "oci_runtime": host.get("ociRuntime", {}).get("name"),
        "oci_runtime_version": (host.get("ociRuntime", {}).get("version") or "").splitlines()[0],
        "rootless": host.get("security", {}).get("rootless"),
        "selinux": host.get("security", {}).get("selinuxEnabled"),
        "seccomp_profile": host.get("security", {}).get("seccompProfilePath") or "podman default",
        "cgroups": host.get("cgroupVersion"),
        "kernel": platform.release(),
        "cpus": host.get("cpus"),
        "cpuset_delegated": cpuset_available(),
    }


def hardening_flags(role: str) -> list:
    lim = LIMITS[role]
    return ["--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=16m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--userns", "auto:size=%d" % userns.USERNS_SIZE, "--user", "%d:%d" % (userns.SANDBOX_UID, userns.SANDBOX_UID),
            "--pids-limit", lim["pids"], "--memory", lim["memory"], "--memory-swap", lim["memory"],
            "--cpus", lim["cpus"]] + (["--cpuset-cpus", lim["cpuset"]] if cpuset_available() else [])


_grants = {}          # container name -> (host uid, [granted paths]); revoked by stop()
_grants_lock = threading.Lock()


def _secret_paths():
    """Files no container may ever be granted: the evidence-signing key, the token file and the model API key file."""
    from . import store
    out = [store.p("keys")]
    if os.environ.get("AEGIS_MODEL_API_KEY_FILE"):
        out.append(Path(os.environ["AEGIS_MODEL_API_KEY_FILE"]))
    return [Path(os.path.realpath(x)) for x in out]


def _check_mounts(mounts):
    for host, _c, _m in mounts:
        real = Path(os.path.realpath(host))
        for sec in _secret_paths():
            if real == sec or sec in real.parents or real in sec.parents:
                raise RuntimeFailure("refusing to mount key material into a container: %s" % host)


def _grant_mounts(name, mounts):
    """Give the container's one mapped host UID access to exactly its mount sources: rw sources (and the directories below
    them) rwx, ro sources r-x on directories and r-- on files. Nothing else changes: owner, mode and other entries stay.
    A mount source that is, contains or lies inside the key directory (or the model API key file) is refused outright."""
    _check_mounts(mounts)
    uid = userns.host_uid(name)
    done = []
    with _grants_lock:
        _grants[name] = (uid, done)
    for host, _ctr, mode in mounts:
        top = Path(host)
        todo = [top]
        if top.is_dir() and not top.is_symlink():
            for d, dirs, files in os.walk(top):
                todo += [Path(d) / x for x in dirs + files]
        for q in todo:
            if q.is_symlink() or not (q.is_dir() or q.is_file()):
                continue
            if q.is_dir():
                userns.grant(q, uid, "rwx" if mode == "rw" else "r-x")
            elif mode == "ro" or q == top:
                userns.grant(q, uid, "rw-" if mode == "rw" else "r--")
            else:
                continue  # an existing file below an rw directory keeps its mode; the container reads what it is meant to
            done.append(q)
    return uid


def _revoke(name):
    with _grants_lock:
        uid, paths = _grants.pop(name, (None, []))
    for q in paths:
        try:
            userns.revoke(q, uid)
        except OSError:
            pass


def mapped_uid(name: str):
    """Host UID that container ``name`` runs as (None if it was not started by this process)."""
    with _grants_lock:
        return _grants.get(name, (None,))[0]


def _create(name, role, mounts, env, argv, detach=True):
    _check_mounts(mounts)
    args = ["podman", "create", "--rm", "--name", name, "--label", "aegislab=1"] + hardening_flags(role)
    for host, ctr, mode in mounts:
        args += ["-v", "%s:%s:%s" % (host, ctr, "ro,Z" if mode == "ro" else "Z")]
    for k, v in env.items():
        args += ["--env", "%s=%s" % (k, v)]
    cid = _run(args + [IMAGE] + list(argv)).stdout.strip()
    try:
        _grant_mounts(name, mounts)
    except RuntimeFailure:
        _run(["podman", "rm", "-f", "-t", "0", name], check=False)
        _revoke(name)
        raise
    except Exception:
        _run(["podman", "rm", "-f", "-t", "0", name], check=False)
        _revoke(name)
        raise RuntimeFailure("could not grant the container's mapped UID access to its mounts")
    return cid


def launch(name: str, role: str, mounts: list, env: dict, cmd: str = None) -> str:
    """mounts: list of (host_path, container_path, mode) with mode 'rw' or 'ro'. create -> grant the mapped UID -> start."""
    cid = _create(name, role, mounts, env, ["python", cmd or COMMANDS[role]])
    out = _run(["podman", "start", name], check=False)
    if out.returncode != 0:
        stop(name)
        raise RuntimeFailure("start: %s" % (out.stderr or "").strip()[-300:])
    return cid


def run_attached(name: str, role: str, mounts: list, argv: list, timeout=None) -> subprocess.CompletedProcess:
    """One-shot container with the same flags, mounts and grants as launch(); waits for it and returns its output and exit
    status (used by the hostile-mailbox probes in tests, the judge demo and the console)."""
    _create(name, role, mounts, {}, argv)
    try:
        return subprocess.run(["podman", "start", "--attach", name], capture_output=True, text=True, timeout=timeout)
    finally:
        stop(name)


def remove_tree(path):
    """Remove a directory a container wrote into. Files and directories a container created belong to its subordinate UID,
    so the broker may lack permission to empty a directory the tenant made; the rest is removed inside the rootless user
    namespace (podman unshare), where those UIDs are mapped."""
    path = Path(path)
    shutil.rmtree(path, ignore_errors=True)
    if os.path.lexists(path):
        _run(["podman", "unshare", "rm", "-rf", "--one-file-system", "--", str(path)], check=False)


def inspect_security(name: str) -> dict:
    out = _run(["podman", "inspect", name], check=False)
    if out.returncode != 0:
        return {"error": "container not running"}
    data = json.loads(out.stdout)[0]
    hc = data.get("HostConfig", {})
    return {
        "selinux_label": data.get("ProcessLabel"),
        "network_mode": hc.get("NetworkMode"),
        "readonly_rootfs": hc.get("ReadonlyRootfs"),
        "cap_add": hc.get("CapAdd"),
        "cap_dropped": len(hc.get("CapDrop") or []),
        "security_opt": hc.get("SecurityOpt"),
        "pids_limit": hc.get("PidsLimit"),
        "memory_bytes": hc.get("Memory"),
        "nano_cpus": hc.get("NanoCpus"),
        "cpuset": hc.get("CpusetCpus"),
    }


def stop(name: str):
    _run(["podman", "rm", "-f", "-t", "0", name], check=False)
    _revoke(name)


def running(name: str) -> bool:
    out = _run(["podman", "container", "exists", name], check=False)
    return out.returncode == 0
