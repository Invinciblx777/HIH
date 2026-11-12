#!/usr/bin/env bash
# AegisLab finale P6 task 6: the reviewer countersignature with the reviewer key OFF the broker host.
#
# The reviewer key is generated on, and only ever read from, the reviewer's device: a teammate's laptop (the real second
# party) or a removable drive. The broker host only ever sees the reviewer's PUBLIC key, which is read out on stage and
# passed to the verifier pinned (--reviewer-pubkey), never taken from the bundle.
#
#   On the REVIEWER device (teammate's laptop with a clone of the repo, or this laptop with the key on a removable drive):
#     offhost_reviewer.sh keygen DEV                 create DEV/aegis-reviewer/reviewer_ed25519.pem (0600); print the public key
#     offhost_reviewer.sh pubkey DEV                 print the public key and its key id again
#     offhost_reviewer.sh countersign DEV BUNDLE --broker-pubkey B64 --run-id ID [--expect-state RELEASED]
#                                                    verify BUNDLE with the pinned broker key, then countersign it with the
#                                                    device's key (writes reviewer_countersignature.json + reviewer_public_key.b64)
#   On the BROKER host (the presenting laptop):
#     offhost_reviewer.sh export ID DEST [--var DIR] export run ID's bundle to DEST (default --var: aegislab/var/console-real);
#                                                    prints the broker public key to pin on the reviewer side
#     offhost_reviewer.sh verify BUNDLE --reviewer-pubkey B64 --broker-pubkey B64 --run-id ID [--expect-state RELEASED]
#                                                    verify_cli --require-countersignature with BOTH keys pinned
#   Rehearsal stand-in for a removable drive (P6 test; says so on every line it prints):
#     offhost_reviewer.sh standin-mount              a 64 MB FAT image in $XDG_RUNTIME_DIR (tmpfs), loop-mounted with udisksctl
#     offhost_reviewer.sh standin-unmount
#
# What this does and does not give (THREAT_MODEL.md row 7 and section 10.7):
#   - teammate's laptop: the key never exists on the broker host. A broker-key forgery cannot produce a matching countersignature.
#   - removable drive in THIS laptop: the key never lies on this laptop's disk, but this laptop's processes read it while
#     countersigning. A host already compromised at that moment could copy it. That is why row 7 stays Partial.
set -Eeuo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd); APP="$REPO/aegislab"
PY="${AEGIS_PYTHON:-$APP/.venv/bin/python}"
export PYTHONDONTWRITEBYTECODE=1
die() { echo "error: $*" >&2; exit 1; }
cmd=${1:-}; shift || true
keyfile() { echo "$1/aegis-reviewer/reviewer_ed25519.pem"; }
same_fs_warning() {  # the key directory must not be on the filesystem that holds $HOME (this laptop's disk)
  local kd=$1
  if [ "$(stat -c %d "$kd")" = "$(stat -c %d "$HOME")" ]; then
    die "$kd is on the same filesystem as \$HOME: that is this laptop's disk, not a reviewer device"
  fi
}
pubkey() {
  (cd "$APP" && "$PY" -c 'import sys; from pathlib import Path; from aegis.crypto import Signer
k = Path(sys.argv[1])
if not k.exists(): sys.exit("no reviewer key at %s" % k)
s = Signer(k); print("reviewer_public_key_b64=" + s.public_b64()); print("reviewer_key_id=" + s.key_id)' "$1")
}
case "$cmd" in
  keygen)
    DEV=${1:?keygen DEV}; mkdir -p "$DEV/aegis-reviewer"; same_fs_warning "$DEV/aegis-reviewer"
    [ -e "$(keyfile "$DEV")" ] && die "a reviewer key already exists on $DEV; refusing to replace it"
    # Written here with O_CREAT|O_EXCL, mode 0600, rather than by aegis.crypto.Signer: Signer publishes a new key with a hard link,
    # which FAT/exFAT (most USB drives) do not support. Same key format (Ed25519, PKCS8 PEM, unencrypted) as Signer reads.
    (cd "$APP" && "$PY" -c 'import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as fh:
    fh.write(pem); fh.flush(); os.fsync(fh.fileno())' "$(keyfile "$DEV")")
    chmod 600 "$(keyfile "$DEV")" 2>/dev/null || true
    echo "reviewer key created on the reviewer device: $(keyfile "$DEV")"
    echo "file mode: $(stat -c %a "$(keyfile "$DEV")") (FAT ignores modes: use an ext4 or encrypted drive for a real key)"
    pubkey "$(keyfile "$DEV")"
    echo "Read the public key out (or show it) to the broker side; it is pinned there with --reviewer-pubkey." ;;
  pubkey)
    pubkey "$(keyfile "${1:?pubkey DEV}")" ;;
  countersign)
    DEV=${1:?countersign DEV BUNDLE ...}; B=${2:?countersign DEV BUNDLE ...}; shift 2
    BROKER=""; RUN=""; STATE=RELEASED
    while [ $# -gt 0 ]; do case "$1" in
      --broker-pubkey) BROKER=$2; shift ;; --run-id) RUN=$2; shift ;; --expect-state) STATE=$2; shift ;; *) die "unknown option $1" ;; esac; shift; done
    [ -n "$BROKER" ] && [ -n "$RUN" ] || die "--broker-pubkey and --run-id are required (the broker key is pinned, never taken from the bundle)"
    K=$(keyfile "$DEV"); [ -f "$K" ] || die "no reviewer key on $DEV (keygen first, on the reviewer device)"
    same_fs_warning "$(dirname "$K")"
    B=$(cd "$B" && pwd)
    (cd "$APP" && "$PY" -m aegis.countersign --bundle "$B" --key "$K" --broker-pubkey "$BROKER" --run-id "$RUN" --expect-state "$STATE") ;;
  export)
    RUN=${1:?export ID DEST}; DEST=${2:?export ID DEST}; shift 2; VAR="$APP/var/console-real"
    while [ $# -gt 0 ]; do case "$1" in --var) VAR=$2; shift ;; *) die "unknown option $1" ;; esac; shift; done
    OUT="$DEST/$RUN-$(date +%H%M%S)"
    (cd "$APP" && AEGIS_VAR="$VAR" "$PY" -c 'import sys; from aegis import evidence; evidence.export_bundle(sys.argv[1], sys.argv[2])' "$RUN" "$OUT")
    # the on-host countersignature written at release (prototype default) is removed from the copy: the reviewer replaces it
    rm -f "$OUT/reviewer_countersignature.json" "$OUT/reviewer_public_key.b64"
    echo "bundle=$OUT"; echo "broker_public_key_b64=$(cat "$OUT/broker_public_key.b64")" ;;
  verify)
    B=${1:?verify BUNDLE ...}; shift; RPUB=""; BPUB=""; RUN=""; STATE=RELEASED
    while [ $# -gt 0 ]; do case "$1" in
      --reviewer-pubkey) RPUB=$2; shift ;; --broker-pubkey) BPUB=$2; shift ;; --run-id) RUN=$2; shift ;; --expect-state) STATE=$2; shift ;; *) die "unknown option $1" ;; esac; shift; done
    [ -n "$RPUB" ] && [ -n "$BPUB" ] && [ -n "$RUN" ] || die "--reviewer-pubkey, --broker-pubkey and --run-id are required (both keys pinned)"
    (cd "$APP" && "$PY" -m aegis.verify_cli --bundle "$B" --pubkey "$BPUB" --run-id "$RUN" --expect-state "$STATE" \
       --require-countersignature --reviewer-pubkey "$RPUB") ;;
  standin-mount)
    IMG="${XDG_RUNTIME_DIR:?}/aegis-reviewer-standin.img"
    [ "$(findmnt -no FSTYPE "$XDG_RUNTIME_DIR")" = tmpfs ] || die "\$XDG_RUNTIME_DIR is not tmpfs; the stand-in image would land on disk"
    [ -e "$IMG" ] && die "$IMG exists (standin-unmount first)"
    truncate -s 64M "$IMG" && mkfs.vfat -n AEGISREV "$IMG" >/dev/null
    LOOP=$(udisksctl loop-setup --no-user-interaction -f "$IMG" | grep -o '/dev/loop[0-9]*')
    sleep 2; MNT=$(findmnt -no TARGET "$LOOP" | head -1)   # GNOME may have auto-mounted it already
    [ -n "$MNT" ] || { udisksctl mount --no-user-interaction -b "$LOOP" >/dev/null; MNT=$(findmnt -no TARGET "$LOOP" | head -1); }
    [ -n "$MNT" ] || die "could not mount $LOOP"
    echo "STAND-IN for a removable drive (P6 test): FAT image in tmpfs ($IMG) on $LOOP, mounted at $MNT"
    echo "standin_mount=$MNT"; echo "standin_loop=$LOOP" ;;
  standin-unmount)
    IMG="${XDG_RUNTIME_DIR:?}/aegis-reviewer-standin.img"
    LOOP=$(losetup -j "$IMG" | cut -d: -f1 | head -1)
    if [ -n "$LOOP" ]; then
      udisksctl unmount --no-user-interaction -b "$LOOP" || true
      sleep 1   # udisks sets autoclear, so the loop device normally goes away with the unmount
      losetup -j "$IMG" | grep -q . && { udisksctl loop-delete --no-user-interaction -b "$LOOP" || echo "loop device $LOOP still attached"; }
    fi
    rm -f "$IMG"; echo "STAND-IN removed (image deleted from tmpfs)" ;;
  *) sed -n '2,30p' "$0"; exit 2 ;;
esac
