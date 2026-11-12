"""Finale P4 (F4): containers never run as the host UID that owns the signing key.

Before P4 every container ran with ``--userns keep-id``, i.e. as the broker's own host UID, which owns the unencrypted
``var/keys/broker_ed25519.pem`` and the model API key file. A container escape was therefore key theft and forgeable
evidence. Now every container (tenants and the sandboxed model server) runs with ``--userns auto`` and a non-root user:

  * podman gives each container its own range of the user's subordinate UIDs (``/etc/subuid``), so container UID
    ``SANDBOX_UID`` is a host UID that is neither the broker's nor any other container's;
  * the key files stay mode 0600 and owned by the broker, so that host UID cannot read them;
  * the broker keeps owning every directory it shares with a container (mailboxes, the model socket directory). It grants the
    one mapped host UID of that container access with a POSIX ACL entry on exactly the mount sources, after ``podman create``
    and before ``podman start`` (the UID is known only once podman has picked the range). Nothing is made group- or
    world-accessible, and the broker's own no-follow I/O is unchanged.

Standard library only: the model-server launcher (scripts/start_model_server.sh) runs this file directly with the system
python3. Command line:

    python3 aegis/userns.py host-uid CONTAINER [CONTAINER_UID]     host UID the container's UID maps to
    python3 aegis/userns.py inner-uid CONTAINER [CONTAINER_UID]    the same UID inside the rootless namespace (podman unshare)
    python3 aegis/userns.py grant PATH HOST_UID rwx|r-x|r--        add or replace one named-user ACL entry
    python3 aegis/userns.py revoke PATH HOST_UID
    python3 aegis/userns.py show PATH
"""
import json
import os
import pwd
import struct
import subprocess
import sys

SANDBOX_UID = 900          # the image's USER (Containerfile) and the --user of every container
USERNS_SIZE = 1024         # subordinate UIDs per container: 0..1023 inside, enough for root-owned image files and SANDBOX_UID
XATTR = "system.posix_acl_access"
_VERSION = 2
USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
UNDEFINED = 0xFFFFFFFF
PERMS = {"rwx": 7, "rw-": 6, "r-x": 5, "r--": 4, "---": 0}


# ------------------------------------------------------------------------------------------------ POSIX ACL xattr
def decode(raw: bytes) -> list:
    """[(tag, perm, id)] from the kernel's posix_acl_xattr format; ValueError on anything else."""
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw)[0] != _VERSION:
        raise ValueError("not a POSIX ACL")
    return [struct.unpack_from("<HHI", raw, 4 + 8 * i) for i in range((len(raw) - 4) // 8)]


def encode(entries) -> bytes:
    return struct.pack("<I", _VERSION) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in sorted(entries))


def entries(path, follow=False) -> list:
    """The access ACL of ``path``; a file without an extended ACL is described by its mode bits (no MASK entry)."""
    try:
        return decode(os.getxattr(path, XATTR, follow_symlinks=follow))
    except OSError as exc:
        if exc.errno not in (61, 95):  # ENODATA (no ACL), EOPNOTSUPP
            raise
    m = os.stat(path, follow_symlinks=follow).st_mode
    return [(USER_OBJ, (m >> 6) & 7, UNDEFINED), (GROUP_OBJ, (m >> 3) & 7, UNDEFINED), (OTHER, m & 7, UNDEFINED)]


def _write(path, ents):
    named = [p for t, p, _ in ents if t in (USER, GROUP)]
    base = [e for e in ents if e[0] != MASK]
    if named:  # the mask bounds the group class; it is recomputed like setfacl does, never wider than the entries need
        gobj = next(p for t, p, _ in ents if t == GROUP_OBJ)
        mask = gobj
        for p in named:
            mask |= p
        base.append((MASK, mask, UNDEFINED))
    os.setxattr(path, XATTR, encode(base), follow_symlinks=False)


def grant(path, uid: int, perms: str):
    """Add or replace the named-user entry for host ``uid`` on ``path`` (never a symlink: lstat-checked, no-follow xattr)."""
    if os.path.islink(path):
        raise OSError(40, "refusing to set an ACL through a symbolic link", str(path))
    ents = [e for e in entries(path) if not (e[0] == USER and e[2] == uid)]
    ents.append((USER, PERMS[perms], int(uid)))
    _write(path, ents)


def revoke(path, uid: int):
    if os.path.islink(path) or not os.path.lexists(path):
        return
    ents = entries(path)
    if any(t == USER and i == uid for t, _, i in ents):
        _write(path, [e for e in ents if not (e[0] == USER and e[2] == uid)])


def named_users(path) -> dict:
    """{host uid: perm} of the named-user entries, plus the effective group-class bits under the key 'group'."""
    ents = entries(path)
    out = {i: p for t, p, i in ents if t == USER}
    mask = next((p for t, p, _ in ents if t == MASK), 7)
    out["group"] = next(p for t, p, _ in ents if t == GROUP_OBJ) & mask
    out["named_groups"] = [i for t, _, i in ents if t == GROUP]
    return out


def private_to(path, owner: int, allowed=()) -> bool:
    """True when only ``owner`` (the file owner) and the host UIDs in ``allowed`` can use ``path``: no group or other bits,
    no named group, no named user outside ``allowed``. Used for the model server's socket directory."""
    st = os.lstat(path)
    if st.st_uid != owner or st.st_mode & 0o007:
        return False
    acl = named_users(path)
    extra = set(k for k in acl if isinstance(k, int)) - set(allowed)
    return acl["group"] == 0 and not acl["named_groups"] and not extra


# ------------------------------------------------------------------------------------------------ podman ID mappings
def subid_ranges(kind="uid", user=None) -> list:
    """[(first host id, count)] for ``user`` from /etc/subuid (or /etc/subgid)."""
    user = user or pwd.getpwuid(os.getuid()).pw_name
    uid = str(os.getuid())
    out = []
    try:
        for line in open("/etc/sub%s" % kind):
            f = line.strip().split(":")
            if len(f) == 3 and f[0] in (user, uid):
                out.append((int(f[1]), int(f[2])))
    except OSError:
        pass
    return out


def inner_to_host(inner: int, ranges=None) -> int:
    """Rootless podman's own namespace: 0 is the user's UID, 1.. are the subordinate UIDs in /etc/subuid order."""
    if inner == 0:
        return os.getuid()
    k = inner - 1
    for first, count in (subid_ranges() if ranges is None else ranges):
        if k < count:
            return first + k
        k -= count
    raise ValueError("UID %d is outside the subordinate range" % inner)


def container_maps(name) -> list:
    """[(container id, rootless-namespace id, count)] of a created container's UID map (podman inspect IDMappings)."""
    out = subprocess.run(["podman", "inspect", name, "--format", "{{json .HostConfig.IDMappings}}"],
                         capture_output=True, text=True, timeout=60)
    if out.returncode:
        raise RuntimeError("podman inspect failed: " + out.stderr.strip()[-200:])
    maps = []
    for m in (json.loads(out.stdout) or {}).get("UidMap") or []:
        c, i, n = (int(x) for x in m.split(":"))
        maps.append((c, i, n))
    return maps


def inner_uid(name, cuid=SANDBOX_UID) -> int:
    for c, i, n in container_maps(name):
        if c <= cuid < c + n:
            return i + cuid - c
    raise ValueError("container UID %d is not mapped (keep-id or host user namespace?)" % cuid)


def host_uid(name, cuid=SANDBOX_UID) -> int:
    """Host UID of container UID ``cuid``. Refuses a mapping onto the caller's own UID: that is the F4 condition."""
    h = inner_to_host(inner_uid(name, cuid))
    if h == os.getuid():
        raise ValueError("container UID %d maps to the broker's own host UID %d" % (cuid, h))
    return h


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd in ("host-uid", "inner-uid") and len(argv) in (3, 4):
        fn = host_uid if cmd == "host-uid" else inner_uid
        print(fn(argv[2], int(argv[3]) if len(argv) == 4 else SANDBOX_UID))
    elif cmd == "grant" and len(argv) == 5 and argv[4] in PERMS:
        grant(argv[2], int(argv[3]), argv[4])
    elif cmd == "revoke" and len(argv) == 4:
        revoke(argv[2], int(argv[3]))
    elif cmd == "show" and len(argv) == 3:
        print(json.dumps({str(k): v for k, v in named_users(argv[2]).items()}))
    else:
        print(__doc__.split("Command line:", 1)[1], file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
