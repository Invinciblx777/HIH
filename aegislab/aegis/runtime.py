"""Container runtime wrapper (rootless Podman + crun in the prototype).

Every tenant workload runs from the same small image with:
  --network none        no network namespace interfaces except loopback
  --read-only           immutable root filesystem, tmpfs /tmp only
  --cap-drop ALL        no Linux capabilities
  no-new-privileges     setuid binaries cannot raise privileges
  --userns keep-id      non-root UID inside the container, rootless on the host
  pids/memory/cpu       cgroup v2 limits; per-tenant cpusets when the cpuset
                        controller is delegated (often not, for rootless)
  :Z volume labels      private SELinux MCS label per container (Fedora/RHEL)
The applied settings are read back with ``podman inspect`` and written to the
audit log, so the evidence reflects what the runtime reports, not the request.
"""
import json
import platform
import subprocess
from pathlib import Path

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
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--userns", "keep-id",
            "--pids-limit", lim["pids"], "--memory", lim["memory"], "--memory-swap", lim["memory"],
            "--cpus", lim["cpus"]] + (["--cpuset-cpus", lim["cpuset"]] if cpuset_available() else [])


def launch(name: str, role: str, mounts: list, env: dict, cmd: str = None) -> str:
    """mounts: list of (host_path, container_path, mode) with mode 'rw' or 'ro'."""
    args = ["podman", "run", "-d", "--rm", "--name", name, "--label", "aegislab=1"] + hardening_flags(role)
    for host, ctr, mode in mounts:
        args += ["-v", "%s:%s:%s" % (host, ctr, "ro,Z" if mode == "ro" else "Z")]
    for k, v in env.items():
        args += ["--env", "%s=%s" % (k, v)]
    args += [IMAGE, "python", cmd or COMMANDS[role]]
    return _run(args).stdout.strip()


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


def running(name: str) -> bool:
    out = _run(["podman", "container", "exists", name], check=False)
    return out.returncode == 0
