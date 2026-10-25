"""Phase 2: attacks and probes executed inside a real rootless Podman sandbox (skipped if Podman or the image is missing).

Each container uses the same hardening flags as a real run (runtime.hardening_flags) and the broker's own mount layout
(Broker._spool_mounts). Resource tests are bounded by the container's own cgroup limits and a timeout.
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import runs, runtime  # noqa: E402

pytestmark = pytest.mark.podman


def _image_ready():
    try:
        return subprocess.run(["podman", "image", "exists", runtime.IMAGE], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [pytest.mark.podman, pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")]


def run_in_sandbox(role, code, mounts=(), timeout=60):
    name = "aegis-p2test-%d" % os.getpid()
    args = ["podman", "run", "--rm", "--name", name, "--label", "aegislab=1"] + runtime.hardening_flags(role)
    for host, ctr, mode in mounts:
        args += ["-v", "%s:%s:%s" % (host, ctr, "ro,Z" if mode == "ro" else "Z")]
    args += [runtime.IMAGE, "python", "-c", textwrap.dedent(code)]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    finally:
        subprocess.run(["podman", "rm", "-f", "-t", "0", name], capture_output=True)


def spool(tmp_path):
    base = tmp_path / "run" / "spool" / "red"
    (base / "in").mkdir(parents=True)
    (base / "out").mkdir()
    return base


def test_P2C01_tenant_cannot_move_or_remove_its_mailbox_directories(tmp_path):
    base = spool(tmp_path)
    r = run_in_sandbox("red", """
        import json, os
        res = {}
        for label, fn in (("rename_in", lambda: os.rename("/aegis/spool/in", "/aegis/spool/in2")),
                          ("rmdir_in", lambda: os.rmdir("/aegis/spool/in")),
                          ("rename_out", lambda: os.rename("/aegis/spool/out", "/aegis/spool/out2")),
                          ("rmdir_out", lambda: os.rmdir("/aegis/spool/out")),
                          ("mkdir_sibling", lambda: os.mkdir("/aegis/spool/other"))):
            try:
                fn(); res[label] = "allowed"
            except OSError as exc:
                res[label] = "denied errno %d" % exc.errno
        print(json.dumps(res))
    """, runs.Broker._spool_mounts(base))
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert all(v.startswith("denied") for v in res.values()), res
    assert (base / "in").is_dir() and (base / "out").is_dir()


def test_P2C02_symlink_planted_from_inside_the_sandbox_does_not_redirect_the_broker(tmp_path):
    base = spool(tmp_path)
    victim = tmp_path / "run" / "audit.jsonl"
    victim.write_text("PHASE2-VICTIM-FILE-MUST-SURVIVE")
    r = run_in_sandbox("red", """
        import os
        os.symlink("../../../audit.jsonl", "/aegis/spool/in/.000002.json.tmp")
        os.mkfifo("/aegis/spool/in/.000003.json.tmp")
        os.mkdir("/aegis/spool/in/000004.json"); open("/aegis/spool/in/000004.json/x", "w").write("x")
        print("planted")
    """, runs.Broker._spool_mounts(base))
    assert r.returncode == 0 and "planted" in r.stdout, r.stderr
    for n in ("000002.json", "000003.json", "000004.json"):
        runs._write_msg(base / "in", n, {"ok": False, "denied": True})
        assert json.loads((base / "in" / n).read_text())["denied"] is True
    assert victim.read_text() == "PHASE2-VICTIM-FILE-MUST-SURVIVE"


def test_P2C10_effective_sandbox_settings_seen_from_inside(tmp_path):
    base = spool(tmp_path)
    r = run_in_sandbox("red", """
        import json, os, socket
        out = {"uid": os.getuid()}
        for line in open("/proc/self/status"):
            k = line.split(":")[0]
            if k in ("CapEff", "CapBnd", "CapPrm", "NoNewPrivs", "Seccomp"):
                out[k] = line.split(":", 1)[1].strip()
        try:
            open("/usr/p2-write-test", "w"); out["rootfs_write"] = "allowed"
        except OSError as exc:
            out["rootfs_write"] = "denied %d" % exc.errno
        try:
            open("/tmp/p2-ok", "w").write("x"); out["tmp_write"] = "allowed"
        except OSError as exc:
            out["tmp_write"] = "denied %d" % exc.errno
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=2); out["net"] = "connected"
        except OSError as exc:
            out["net"] = "failed %d" % exc.errno
        out["interfaces"] = sorted(os.listdir("/sys/class/net"))
        out["cgroup_memory_max"] = open("/sys/fs/cgroup/memory.max").read().strip()
        out["cgroup_pids_max"] = open("/sys/fs/cgroup/pids.max").read().strip()
        out["visible_aegis_paths"] = sorted(p for p in ("/aegis/frozen", "/aegis/sealed", "/aegis/private", "/aegis/spool/in", "/aegis/spool/out", "/aegis/spool/blue") if os.path.exists(p))
        print(json.dumps(out))
    """, runs.Broker._spool_mounts(base))
    assert r.returncode == 0, r.stderr
    o = json.loads(r.stdout.strip().splitlines()[-1])
    assert o["uid"] != 0
    assert o["CapEff"] == o["CapBnd"] == o["CapPrm"] == "0000000000000000"
    assert o["NoNewPrivs"] == "1" and o["Seccomp"] == "2"
    assert o["rootfs_write"].startswith("denied") and o["tmp_write"] == "allowed"
    assert o["net"].startswith("failed") and o["interfaces"] == ["lo"]
    assert o["cgroup_memory_max"] == str(256 * 1024 * 1024) and o["cgroup_pids_max"] == "64"
    assert o["visible_aegis_paths"] == ["/aegis/spool/in", "/aegis/spool/out"]


def test_P2C11_process_limit_is_enforced_and_bounded(tmp_path):
    r = run_in_sandbox("red", """
        import os, sys, time
        kids = []
        try:
            for _ in range(200):
                pid = os.fork()
                if pid == 0:
                    time.sleep(20); os._exit(0)
                kids.append(pid)
        except OSError as exc:
            print("fork refused after", len(kids), "children errno", exc.errno)
        finally:
            for k in kids:
                os.kill(k, 9)
    """, timeout=60)
    assert "fork refused after" in r.stdout, (r.stdout, r.stderr)
    assert int(r.stdout.split("after")[1].split()[0]) <= 64


def test_P2C12_memory_limit_kills_a_runaway_allocation(tmp_path):
    r = run_in_sandbox("red", """
        chunks = []
        while True:
            chunks.append(bytearray(32 * 1024 * 1024))
    """, timeout=60)
    assert r.returncode != 0, "a sandbox allocated without limit"


def test_P2C13_model_worker_role_sees_only_its_own_mailbox_and_cannot_reach_run_files(tmp_path):
    base = spool(tmp_path)
    (tmp_path / "run" / "sealed").mkdir()
    (tmp_path / "run" / "sealed" / "canary.json").write_text('{"canary":"CANARY-000000000000"}')
    r = run_in_sandbox("model", """
        import json, os, socket
        res = {}
        for p in ("/aegis/frozen", "/aegis/private", "/aegis/sealed", "/aegis/spool/red", "/aegis/spool/blue", "/run", "/var/lib/aegis",
                  "/proc/1/root", "../run/sealed/canary.json", "/aegis/spool/../sealed"):
            res[p] = os.path.exists(p) and (os.path.isdir(p) and bool(os.listdir(p)) or os.path.isfile(p))
        try:
            os.symlink("/aegis/spool/in", "/aegis/spool/out/link"); res["symlink_in_own_out"] = "allowed"
        except OSError as exc:
            res["symlink_in_own_out"] = "denied %d" % exc.errno
        for what, fn in (("setuid", lambda: os.setuid(0)), ("chroot", lambda: os.chroot("/tmp")),
                         ("mount", lambda: os.system("mount -t tmpfs x /tmp 2>/dev/null") or 1)):
            try:
                fn(); res[what] = "allowed" if what != "mount" else "ran"
            except OSError as exc:
                res[what] = "denied %d" % exc.errno
        print(json.dumps(res))
    """, runs.Broker._spool_mounts(base))
    assert r.returncode == 0, r.stderr
    o = json.loads(r.stdout.strip().splitlines()[-1])
    for p in ("/aegis/frozen", "/aegis/private", "/aegis/sealed", "/aegis/spool/red", "/aegis/spool/blue", "/aegis/spool/../sealed",
              "../run/sealed/canary.json"):
        assert o[p] is False, (p, o[p])
    assert o["setuid"].startswith("denied") and o["chroot"].startswith("denied")


def test_P2C14_defence_runner_role_cannot_modify_its_frozen_config_or_see_tenant_data(tmp_path):
    base = spool(tmp_path)
    frozen = tmp_path / "run" / "frozen"
    frozen.mkdir()
    (frozen / "defence_config.json").write_text('{"input_patterns":[]}')
    r = run_in_sandbox("blue", """
        import json, os
        res = {}
        for label, fn in (("write_frozen", lambda: open("/aegis/frozen/defence_config.json", "w")),
                          ("create_in_frozen", lambda: open("/aegis/frozen/new.json", "w")),
                          ("unlink_frozen", lambda: os.unlink("/aegis/frozen/defence_config.json"))):
            try:
                fn(); res[label] = "allowed"
            except OSError as exc:
                res[label] = "denied %d" % exc.errno
        res["private_visible"] = os.path.exists("/aegis/private")
        res["red_spool_visible"] = os.path.exists("/aegis/spool/red")
        print(json.dumps(res))
    """, runs.Broker._spool_mounts(base) + [(str(frozen), "/aegis/frozen", "ro")])
    assert r.returncode == 0, r.stderr
    o = json.loads(r.stdout.strip().splitlines()[-1])
    assert all(o[k].startswith("denied") for k in ("write_frozen", "create_in_frozen", "unlink_frozen")), o
    assert o["private_visible"] is False and o["red_spool_visible"] is False
    assert (frozen / "defence_config.json").read_text() == '{"input_patterns":[]}'


# ---------------------------------------------------------------- cleanup after exceptions and interrupted runs (real containers)
def leftover(run_id):
    out = subprocess.run(["podman", "ps", "-a", "--filter", "label=aegislab=1", "--format", "{{.Names}}"], capture_output=True, text=True)
    return [n for n in out.stdout.split() if run_id.lower() in n]


@pytest.fixture
def live_state(tmp_path, monkeypatch):
    from aegis import store
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    monkeypatch.setattr(runs, "_signer", None)
    return store


def test_P2C20_exception_after_the_workloads_started_leaves_no_container_and_a_verifying_failed_run(live_state, monkeypatch):
    def explode(self, complete):
        raise RuntimeError("injected failure after start")
    monkeypatch.setattr(runs.Broker, "seal", explode)
    runs.create_run("C20", timing_bucket_ms=0)
    runs.freeze("C20")
    runs.start("C20", wait=True)
    run = runs.Run("C20")
    assert run.state == "FAILED"
    v = runs.verify_run("C20")
    assert v["ok"] and v["terminal_state"] == "FAILED"
    assert leftover("C20") == []
    with pytest.raises(runs.GateError):
        runs.release("C20")


def test_P2C21_red_sandbox_killed_mid_run_ends_sealed_incomplete_and_cleans_up(live_state, monkeypatch):
    import threading, time
    runs.create_run("C21", timing_bucket_ms=250)
    runs.freeze("C21")
    t = runs.start("C21")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not runtime.running("aegis-c21-red"):
        time.sleep(0.05)
    time.sleep(0.4)
    subprocess.run(["podman", "rm", "-f", "-t", "0", "aegis-c21-red"], capture_output=True)  # the red workload vanishes mid-run
    t.join(60)
    assert not t.is_alive()
    run = runs.Run("C21")
    assert run.state in ("SEALED", "FAILED")
    if run.state == "SEALED":
        assert run.record.get("complete") is False
        runs.release("C21")
    assert runs.verify_run("C21")["ok"]
    assert leftover("C21") == []
