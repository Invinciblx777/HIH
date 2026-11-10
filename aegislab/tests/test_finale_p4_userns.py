"""Finale P4, task 2 (F4): no container runs as the key owner's UID.

Container-free: the flags, the image user, the ACL helper, the subordinate-UID arithmetic, the expected-owner socket check,
the key-mount guard and the broker's handling of a tenant tree it cannot delete. Podman-marked: from the host, each container
process's UID is its own subordinate UID (never the broker's, never another container's); a deliberately mounted signing key
is unreadable inside; a socket owned by the mapped UID is accepted only when that exact UID is expected.
"""
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import model_client as mc, runs, runtime, store, userns  # noqa: E402
from aegis.crypto import Signer  # noqa: E402

ME = os.geteuid()


# ---------------------------------------------------------------- flags and image
@pytest.mark.parametrize("role", ["red", "blue", "model"])
def test_P4U01_every_role_runs_userns_auto_as_non_root_never_keep_id(role):
    f = runtime.hardening_flags(role)
    assert "keep-id" not in f
    assert f[f.index("--userns") + 1] == "auto:size=%d" % userns.USERNS_SIZE
    assert f[f.index("--user") + 1] == "%d:%d" % (userns.SANDBOX_UID, userns.SANDBOX_UID)
    assert 0 < userns.SANDBOX_UID < userns.USERNS_SIZE


def test_P4U02_image_user_is_non_root():
    cf = (ROOT / "Containerfile").read_text()
    assert "USER %d:%d" % (userns.SANDBOX_UID, userns.SANDBOX_UID) in cf.splitlines()
    sh = (ROOT / "scripts/start_model_server.sh").read_text()
    assert "--userns keep-id" not in sh and '--userns "auto:size=$USERNS_SIZE"' in sh and '--user "$SANDBOX_UID:$SANDBOX_UID"' in sh
    assert "SANDBOX_UID=%d; USERNS_SIZE=%d" % (userns.SANDBOX_UID, userns.USERNS_SIZE) in sh


# ---------------------------------------------------------------- ACL helper and UID arithmetic
def test_P4U03_acl_encode_decode_round_trip_and_grant_revoke(tmp_path):
    ents = [(userns.USER_OBJ, 7, userns.UNDEFINED), (userns.USER, 7, 600001), (userns.GROUP_OBJ, 0, userns.UNDEFINED),
            (userns.MASK, 7, userns.UNDEFINED), (userns.OTHER, 0, userns.UNDEFINED)]
    assert userns.decode(userns.encode(ents)) == sorted(ents)
    with pytest.raises(ValueError):
        userns.decode(b"\x01\x00\x00\x00" + b"\x00" * 8)
    d = tmp_path / "box"
    d.mkdir(mode=0o700)
    userns.grant(d, 600001, "rwx")
    acl = userns.named_users(d)
    assert acl[600001] == 7 and acl["group"] == 0 and acl["named_groups"] == []
    assert userns.private_to(d, ME, [600001]) and not userns.private_to(d, ME, [])
    userns.revoke(d, 600001)
    assert 600001 not in userns.named_users(d) and userns.private_to(d, ME, [])
    link = tmp_path / "link"
    link.symlink_to(d)
    with pytest.raises(OSError):
        userns.grant(link, 600001, "rwx")


def test_P4U04_rootless_namespace_to_host_uid_arithmetic(monkeypatch):
    r = [(524288, 65536)]
    assert userns.inner_to_host(0, r) == os.getuid()
    assert userns.inner_to_host(1, r) == 524288 and userns.inner_to_host(65536, r) == 524288 + 65535
    with pytest.raises(ValueError):
        userns.inner_to_host(65537, r)
    assert userns.inner_to_host(3, [(100000, 2), (300000, 10)]) == 300000
    monkeypatch.setattr(userns, "container_maps", lambda name: [(0, 1001, 1024)])
    monkeypatch.setattr(userns, "subid_ranges", lambda *a, **k: r)
    assert userns.inner_uid("x") == 1001 + userns.SANDBOX_UID
    assert userns.host_uid("x") == 524288 + 1000 + userns.SANDBOX_UID


def test_P4U05_a_mapping_onto_the_broker_uid_is_refused(monkeypatch):
    """--userns keep-id maps the container user onto rootless-namespace 0, i.e. the broker's own UID: the F4 condition."""
    monkeypatch.setattr(userns, "container_maps", lambda name: [(userns.SANDBOX_UID, 0, 1), (0, 1, userns.SANDBOX_UID)])
    with pytest.raises(ValueError, match="broker's own host UID"):
        userns.host_uid("x")
    monkeypatch.setattr(userns, "container_maps", lambda name: [(0, 1, 10)])
    with pytest.raises(ValueError, match="not mapped"):
        userns.host_uid("x")


# ---------------------------------------------------------------- expected-owner socket check
def _sock(d):
    d.mkdir(mode=0o700, exist_ok=True)
    p = d / "s.sock"
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(p))
    return s, p


def test_P4U06_socket_owned_by_this_user_passes_only_when_this_user_is_expected(tmp_path):
    s, p = _sock(tmp_path / "sock")
    try:
        mc.check_unix_socket(str(p))
        mc.check_unix_socket(str(p), -1)
        with pytest.raises(mc.ModelBackendError) as e:
            mc.check_unix_socket(str(p), 600001)  # expected the mapped UID, found the broker's own: refused
        assert e.value.kind == "config"
    finally:
        s.close()


def test_P4U07_socket_directory_must_name_no_one_but_the_expected_owner(tmp_path):
    s, p = _sock(tmp_path / "sock")
    try:
        userns.grant(p.parent, 600002, "rwx")  # someone else granted: refused even for the broker-owned socket
        with pytest.raises(mc.ModelBackendError):
            mc.check_unix_socket(str(p))
        userns.revoke(p.parent, 600002)
        mc.check_unix_socket(str(p))
        os.chmod(p.parent, 0o710)
        with pytest.raises(mc.ModelBackendError):
            mc.check_unix_socket(str(p))
        os.chmod(p.parent, 0o700)
        link = p.parent / "l.sock"
        link.symlink_to(p)
        with pytest.raises(mc.ModelBackendError):
            mc.check_unix_socket(str(link))
    finally:
        s.close()


def test_P4U08_owner_setting_needs_a_socket_and_is_never_the_broker_uid():
    base = {"AEGIS_MODEL_BACKEND": "openai_compatible", "AEGIS_MODEL_BASE_URL": "http://localhost/v1", "AEGIS_MODEL_NAME": "m",
            "AEGIS_MODEL_UNIX_SOCKET": "/run/user/1000/aegis-model.x/sock/llama.sock"}
    cfg = mc.load_config(dict(base, AEGIS_MODEL_UNIX_SOCKET_OWNER_UID="525188"))
    assert cfg.unix_socket_owner == 525188 and cfg.describe()["unix_socket_owner_uid"] == 525188
    assert mc.load_config(base).unix_socket_owner == -1 and "unix_socket_owner_uid" not in mc.load_config(base).describe()
    for bad in (str(ME), "-1", "abc", "0", "4294967295"):
        with pytest.raises(mc.ModelBackendError):
            mc.load_config(dict(base, AEGIS_MODEL_UNIX_SOCKET_OWNER_UID=bad))
    no_sock = {k: v for k, v in base.items() if k != "AEGIS_MODEL_UNIX_SOCKET"}
    with pytest.raises(mc.ModelBackendError):
        mc.load_config(dict(no_sock, AEGIS_MODEL_UNIX_SOCKET_OWNER_UID="525188"))


# ---------------------------------------------------------------- key-mount guard, undeletable tenant trees
def test_P4U09_key_material_is_never_mounted_into_a_container(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    key = store.p("keys", "broker_ed25519.pem")
    Signer(key)
    mk = tmp_path / "model.key"
    mk.write_text("k")
    monkeypatch.setenv("AEGIS_MODEL_API_KEY_FILE", str(mk))
    for src in (key, key.parent, store.VAR, mk):
        with pytest.raises(runtime.RuntimeFailure, match="key material"):
            runtime._check_mounts([(str(src), "/x", "ro")])
    (store.VAR / "runs").mkdir()
    runtime._check_mounts([(str(store.VAR / "runs"), "/x", "rw")])
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and key.stat().st_uid == ME


def test_P4U10_tenant_tree_the_broker_cannot_empty_is_moved_aside_and_the_reply_still_lands(tmp_path):
    box = tmp_path / "in"
    box.mkdir()
    tree = box / "000004.json"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "x").write_text("x")
    os.chmod(tree / "sub", 0o500)  # like a tenant-owned directory: the broker may not remove what is inside
    try:
        runs._write_msg(box, "000004.json", {"ok": True})
        assert json.loads((box / "000004.json").read_text()) == {"ok": True}
        assert runs._entries(box) == ["000004.json"]
        assert [n for n in os.listdir(box) if n.startswith(runs.TRASH_PREFIX)]
        assert runs._list_messages(box) == ["000004.json"]
        assert stat.S_IMODE((box / "000004.json").stat().st_mode) == 0o644
    finally:
        for d, _, _ in os.walk(box):
            os.chmod(d, 0o700)
    runtime.remove_tree(box)
    assert not box.exists()


# ---------------------------------------------------------------- live (rootless Podman)
def _image_ready():
    try:
        return subprocess.run(["podman", "image", "exists", runtime.IMAGE], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


live = [pytest.mark.podman, pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")]


def _status_uid(pid):
    for ln in Path("/proc/%d/status" % pid).read_text().splitlines():
        if ln.startswith("Uid:"):
            return [int(x) for x in ln.split()[1:]]


@pytest.mark.podman
@pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")
def test_P4U20_host_sees_each_container_as_its_own_subordinate_uid_never_the_broker(tmp_path):
    names = ["aegis-p4u20-%d-%d" % (os.getpid(), i) for i in range(2)]
    try:
        for n in names:
            d = tmp_path / n
            (d / "in").mkdir(parents=True)
            (d / "out").mkdir()
            runtime._create(n, "red", runs.Broker._spool_mounts(d), {}, ["python", "-c", "import time; time.sleep(30)"])
            subprocess.run(["podman", "start", n], capture_output=True, check=True)
        uids = []
        for n in names:
            pid = int(subprocess.run(["podman", "inspect", n, "--format", "{{.State.Pid}}"], capture_output=True, text=True).stdout)
            u = _status_uid(pid)
            assert len(set(u)) == 1, u  # real, effective, saved and filesystem UID agree
            assert u[0] == runtime.mapped_uid(n) and u[0] != ME and u[0] != 0
            lo, n_ = userns.subid_ranges()[0]
            assert lo <= u[0] < lo + n_
            assert userns.named_users(tmp_path / n / "in")[u[0]] == 7  # exactly this UID was granted its mailbox
            uids.append(u[0])
        assert uids[0] != uids[1]
    finally:
        for n in names:
            runtime.stop(n)
    for n in names:
        assert runtime.mapped_uid(n) is None and set(userns.named_users(tmp_path / n / "in")) == {"group", "named_groups"}


@pytest.mark.podman
@pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")
def test_P4U21_negative_control_a_deliberately_mounted_signing_key_is_unreadable_inside(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "VAR", tmp_path / "var")
    key = store.p("keys", "broker_ed25519.pem")
    Signer(key)
    code = ("import json\ntry:\n    open('/k/broker_ed25519.pem','rb').read(); print(json.dumps({'read': 'ALLOWED'}))\n"
            "except OSError as e:\n    print(json.dumps({'read': 'denied', 'errno': e.errno}))\n")
    # the guard refuses to set this up through the runtime at all ...
    with pytest.raises(runtime.RuntimeFailure, match="key material"):
        runtime.run_attached("aegis-p4u21-%d" % os.getpid(), "red", [(str(key.parent), "/k", "ro")], ["python", "-c", code])
    # ... and a raw podman run with the same flags, mounting it on purpose, still cannot read it
    name = "aegis-p4u21raw-%d" % os.getpid()
    try:
        r = subprocess.run(["podman", "run", "--rm", "--name", name] + runtime.hardening_flags("red") +
                           ["-v", "%s:/k:ro,Z" % key.parent, runtime.IMAGE, "python", "-c", code], capture_output=True, text=True, timeout=60)
    finally:
        subprocess.run(["podman", "rm", "-f", "-t", "0", name], capture_output=True)
    assert json.loads(r.stdout.strip().splitlines()[-1]) == {"read": "denied", "errno": 13}, r.stderr


@pytest.mark.podman
@pytest.mark.skipif(not _image_ready(), reason="Podman or the sandbox image is not available")
def test_P4U22_socket_of_a_mapped_uid_is_accepted_only_for_that_expected_uid(tmp_path):
    d = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / ("p4u22-%d" % os.getpid())  # short path: sun_path is 108 bytes
    d.mkdir(mode=0o700)
    p = d / "s.sock"
    inner = 1000 + userns.SANDBOX_UID
    code = ("import socket, os, time\ns = socket.socket(socket.AF_UNIX); s.bind(%r); os.chown(%r, %d, %d); print('ok', flush=True)\n"
            "time.sleep(20)\n") % (str(p), str(p), inner, inner)
    pr = subprocess.Popen(["podman", "unshare", "python3", "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert pr.stdout.readline().strip() == "ok"
        host = userns.inner_to_host(inner)
        assert os.lstat(p).st_uid == host != ME
        with pytest.raises(mc.ModelBackendError):
            mc.check_unix_socket(str(p))  # P3 rule (broker-owned) refuses it
        userns.grant(d, host + 7, "rwx")
        with pytest.raises(mc.ModelBackendError):
            mc.check_unix_socket(str(p), host)  # the directory grants someone other than the expected UID: refused
        userns.revoke(d, host + 7)
        userns.grant(d, host, "rwx")
        mc.check_unix_socket(str(p), host)  # exactly the expected mapped UID: accepted
        for wrong in (host + 1, 0, ME):
            with pytest.raises(mc.ModelBackendError):
                mc.check_unix_socket(str(p), wrong)
    finally:
        pr.kill()
        pr.wait()
        runtime.remove_tree(d)
