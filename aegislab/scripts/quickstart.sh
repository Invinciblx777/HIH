#!/usr/bin/env bash
# AegisLab one-command start: prerequisites, virtualenv, dependencies, sandbox image, tests, DEMO-001,
# independent evidence verification, and (optionally) the web console.
#
#   scripts/quickstart.sh             run every stage, print the console command, exit
#   scripts/quickstart.sh --serve     ...then run the console in the FOREGROUND (Ctrl-C stops it; no background process)
#   scripts/quickstart.sh --port 8500 use another console port
#
# Safe to repeat. State goes to $AEGIS_VAR (default var/quickstart), never to the submitted evidence/ folder or
# to var/DEMO-001. Delete var/quickstart to start from scratch. Only containers labelled aegislab=1 that this
# project starts are ever stopped, and the broker does that itself.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

SERVE=0; PORT=8400
while [ $# -gt 0 ]; do
  case "$1" in
    --serve) SERVE=1 ;;
    --port) PORT="${2:?--port needs a number}"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

export AEGIS_VAR="${AEGIS_VAR:-$ROOT/var/quickstart}"
BUNDLE="$AEGIS_VAR/bundles/DEMO-001"
IMAGE_BASE="docker.io/library/python:3.12-slim"
RESULTS=()

if [ -t 1 ]; then OK=$'\e[32mPASS\e[0m'; BAD=$'\e[31mFAIL\e[0m'; else OK=PASS; BAD=FAIL; fi

summary() {
  echo; echo "== AegisLab quickstart summary =="
  printf '  %s\n' "${RESULTS[@]}"
}
fail() {  # fail <stage> <what happened> <what to do>
  RESULTS+=("$BAD  $1")
  echo; echo "ERROR in stage '$1': $2" >&2
  echo "  -> $3" >&2
  summary; exit 1
}
pass() { RESULTS+=("$OK  $1${2:+ ($2)}"); echo "[$OK] $1${2:+ ($2)}"; }

# 1 --------------------------------------------------------------------------------- prerequisites
echo "[1/8] prerequisites"
command -v python3 >/dev/null || fail prerequisites "python3 not found" "install Python 3.11+ (Fedora: sudo dnf install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail prerequisites "Python $(python3 -V 2>&1) is older than 3.11" "install Python 3.11 or newer"
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || fail prerequisites "python3 venv/ensurepip missing" "install it (Debian/Ubuntu: sudo apt install python3-venv)"
command -v podman >/dev/null || fail prerequisites "podman not found" "install rootless Podman (Fedora: sudo dnf install podman; Debian/Ubuntu: sudo apt install podman)"
[ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo unknown)" = "true" ] \
  || fail prerequisites "Podman is not running rootless for this user (or 'podman info' failed)" "run as a normal user; check 'podman info'; AegisLab never needs root"
pass prerequisites "python $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'), podman $(podman --version | awk '{print $3}') rootless"

# 2 --------------------------------------------------------------------------------- virtualenv
echo "[2/8] virtualenv (.venv, no global installs)"
[ -x .venv/bin/python ] || python3 -m venv .venv || fail virtualenv "could not create .venv" "check disk space and write permission in $ROOT"
# shellcheck disable=SC1091
. .venv/bin/activate
pass virtualenv ".venv"

# 3 --------------------------------------------------------------------------------- dependencies
echo "[3/8] dependencies (requirements.txt)"
pip install -q -r requirements.txt \
  || fail dependencies "pip install failed" "check network access to PyPI or point pip at a local mirror (PIP_INDEX_URL); already-installed packages are reused"
pass dependencies "$(pip list --format=freeze 2>/dev/null | grep -ciE '^(fastapi|uvicorn|cryptography|pytest|httpx)==') core packages"

# 4 --------------------------------------------------------------------------------- container image
echo "[4/8] sandbox image"
if ! podman image exists "$IMAGE_BASE"; then
  echo "  pulling $IMAGE_BASE"
  podman pull -q "$IMAGE_BASE" >/dev/null \
    || fail image "could not pull $IMAGE_BASE" "check network/registry access, or 'podman load' the image from another machine and re-run"
fi
python -c 'from aegis import runtime, store; print("  sandbox image id:", runtime.build_image(store.ROOT)[:19])' \
  || fail image "could not build the sandbox image from Containerfile" "run 'podman build -f Containerfile .' to see the full error"
pass image "$IMAGE_BASE + localhost/aegislab-sandbox"

# 5 --------------------------------------------------------------------------------- tests
echo "[5/8] test suite (includes the security regression tests and one end-to-end run on Podman)"
if ! pytest -q tests; then
  fail tests "one or more tests failed - including security tests, so nothing further is trusted" "read the failure above; do not use this checkout for a demo until the suite passes"
fi
pass tests "pytest -q tests"

# 6 --------------------------------------------------------------------------------- DEMO-001
echo "[6/8] DEMO-001 (state in $AEGIS_VAR)"
mkdir -p "$AEGIS_VAR"
if [ -f "$AEGIS_VAR/runs/DEMO-001/run.json" ]; then
  STATE=$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$AEGIS_VAR/runs/DEMO-001/run.json")
  [ "$STATE" = "RELEASED" ] || fail demo "existing DEMO-001 in $AEGIS_VAR is $STATE" "delete $AEGIS_VAR (it only holds quickstart state) and re-run"
  pass demo "reusing existing RELEASED DEMO-001 from an earlier quickstart"
else
  python scripts/demo_run.py DEMO-001 --bundle-dir "$BUNDLE" || fail demo "DEMO-001 did not reach RELEASED with a verified terminal checkpoint" \
    "re-run 'python scripts/demo_run.py DEMO-002' to see the full output; check 'podman ps -a --filter label=aegislab=1'"
  pass demo "RELEASED, terminal checkpoint verified"
fi
[ -d "$BUNDLE" ] || python -c 'from aegis import evidence; print(evidence.export_bundle("DEMO-001", "'"$BUNDLE"'"))' \
  || fail demo "could not export the evidence bundle" "see the error above"

# 7 --------------------------------------------------------------------------------- independent verification
echo "[7/8] independent evidence verification"
python -m aegis.verify_cli --bundle "$BUNDLE" >/dev/null \
  || fail verify "the exported evidence bundle does not verify" "run 'python -m aegis.verify_cli --bundle $BUNDLE' to see the findings"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cp -r "$BUNDLE" "$TMP/tampered"
head -n -3 "$BUNDLE/audit.jsonl" > "$TMP/tampered/audit.jsonl"   # drop the last 3 entries of a COPY
if python -m aegis.verify_cli --bundle "$TMP/tampered" >/dev/null 2>&1; then
  fail verify "a truncated COPY of the evidence was accepted" "this is a security failure - do not use this build"
fi
rm -rf "$TMP"; trap - EXIT
pass verify "genuine bundle accepted; truncated copy rejected"

# 8 --------------------------------------------------------------------------------- console
echo "[8/8] console"
CMD="AEGIS_VAR=\"$AEGIS_VAR\" AEGIS_DEMO_MODE=1 .venv/bin/uvicorn aegis.api:app --host 127.0.0.1 --port $PORT"
pass console "not started automatically"
summary
echo
echo "Everything passed. Evidence bundle: $BUNDLE"
echo "Re-verify any time:  .venv/bin/python -m aegis.verify_cli --bundle $BUNDLE"
echo "Launch the console:  $CMD"
echo "Security demo:       scripts/security_demo.sh"
if [ "$SERVE" = 1 ]; then
  python - "$PORT" <<'PY' || { echo "port $PORT is already in use; choose another with --port" >&2; exit 1; }
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) else 1)
PY
  echo "Serving on http://127.0.0.1:$PORT (demo identities enabled, loopback only). Ctrl-C to stop."
  AEGIS_DEMO_MODE=1 exec .venv/bin/uvicorn aegis.api:app --host 127.0.0.1 --port "$PORT"
fi
