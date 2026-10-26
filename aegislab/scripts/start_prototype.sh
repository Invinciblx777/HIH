#!/usr/bin/env bash
# AegisLab interactive prototype console (Phase R1): checks prerequisites, prepares the environment, serves the console on loopback.
#
#   scripts/start_prototype.sh              start on http://127.0.0.1:8400 (Ctrl-C stops it)
#   scripts/start_prototype.sh --port 8500  use another port
#   scripts/start_prototype.sh --check      run the checks only, start nothing
#   scripts/start_prototype.sh --reset      delete the console's state directory (var/console) first
#
# Live mode needs rootless Podman and the sandbox image (built here on first use). Without them the console still starts in
# degraded mode: evidence verification works, live scenarios are disabled and a recorded execution is shown instead.
# State goes to var/console (AEGIS_VAR). Nothing under evidence/, var/quickstart or the submission files is written.
# The console binds to 127.0.0.1 only and enables local demo identities; never expose it beyond loopback.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=8400; CHECK=0; RESET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?--port needs a number}"; shift ;;
    --check) CHECK=1 ;;
    --reset) RESET=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || { echo "--port must be a number between 1024 and 65535" >&2; exit 2; }

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else G=; Y=; R=; N=; fi
ok()   { echo "  ${G}ok${N}    $*"; }
warn() { echo "  ${Y}warn${N}  $*"; }
die()  { echo "  ${R}fail${N}  $1" >&2; echo "        -> $2" >&2; exit 1; }

export AEGIS_VAR="$ROOT/var/console"
export PYTHONDONTWRITEBYTECODE=1
for k in $(env | sed -n 's/^\(AEGIS_MODEL[A-Z_]*\)=.*/\1/p'); do unset "$k"; done   # the console always uses the deterministic stub model

echo "AegisLab prototype console: prerequisites"
command -v python3 >/dev/null || die "python3 not found" "install Python 3.11+ (Fedora: sudo dnf install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python $(python3 -V 2>&1) is older than 3.11" "install Python 3.11 or newer"
ok "python $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

if [ ! -x .venv/bin/python ]; then
  python3 -c 'import venv, ensurepip' 2>/dev/null || die "python3 venv/ensurepip missing" "install it (Debian/Ubuntu: sudo apt install python3-venv)"
  python3 -m venv .venv || die "could not create .venv" "check disk space and write permission in $ROOT"
fi
if ! .venv/bin/python -c 'import fastapi, uvicorn, cryptography, httpx' 2>/dev/null; then
  echo "        installing requirements.txt into .venv"
  .venv/bin/pip install -q -r requirements.txt || die "pip install failed" "check network access to PyPI (or PIP_INDEX_URL) and re-run"
fi
ok "virtualenv .venv with fastapi, uvicorn, cryptography, httpx"

LIVE=1
if ! command -v podman >/dev/null; then
  LIVE=0; warn "podman not found: degraded mode (live scenarios off). Fedora: sudo dnf install podman"
elif [ "$(timeout 20 podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)" != "true" ]; then
  LIVE=0; warn "podman is not usable rootless for this user: degraded mode. Check 'podman info'; AegisLab never needs root"
else
  ok "podman $(podman --version | awk '{print $3}'), rootless"
  if ! podman image exists localhost/aegislab-sandbox:0.1 || [ "$CHECK" = 0 ]; then
    if ! podman image exists docker.io/library/python:3.12-slim; then
      echo "        pulling docker.io/library/python:3.12-slim (first run only)"
      podman pull -q docker.io/library/python:3.12-slim >/dev/null || { LIVE=0; warn "could not pull the base image: degraded mode (check network, or 'podman load' it)"; }
    fi
    if [ "$LIVE" = 1 ] && [ "$CHECK" = 0 ]; then
      .venv/bin/python -c 'from aegis import runtime, store; runtime.build_image(store.ROOT)' >/dev/null \
        || { LIVE=0; warn "could not build the sandbox image: degraded mode (run 'podman build -f Containerfile .' for details)"; }
    fi
  fi
  if [ "$LIVE" = 1 ]; then
    podman image exists localhost/aegislab-sandbox:0.1 && ok "sandbox image localhost/aegislab-sandbox:0.1 $([ "$CHECK" = 1 ] && echo present || echo "(rebuilt from Containerfile)")" || { LIVE=0; warn "sandbox image not built yet (start without --check builds it)"; }
  fi
fi

if [ "$RESET" = 1 ] && [ -d "$AEGIS_VAR" ]; then
  rm -rf -- "$AEGIS_VAR"; ok "reset: removed var/console"
fi
mkdir -p "$AEGIS_VAR"

.venv/bin/python - "$PORT" <<'PY' || die "port $PORT is already in use" "stop the other process or choose another port with --port"
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) else 1)
PY
ok "port $PORT free on 127.0.0.1"

echo
if [ "$LIVE" = 1 ]; then
  echo "Mode: LIVE. Scenarios start real rootless containers. Model: deterministic STUB (not an LLM)."
else
  echo "Mode: DEGRADED. Evidence verification works; live scenarios are disabled; the console shows a RECORDED execution instead."
fi
echo "Real-model results in the console are PRECOMPUTED from saved runs; no model runs here."
[ "$CHECK" = 1 ] && { echo "Checks done (--check): nothing started."; exit 0; }

cleanup() {
  # only containers this console may have left behind: label aegislab=1 and a lab-run or probe name
  local left
  left=$(podman ps -a --filter label=aegislab=1 --format '{{.Names}}' 2>/dev/null | grep -E '^aegis-(lab-[0-9]{3}-(red|blue|model)|lab-probe-[0-9a-f]{8})$' || true)
  [ -n "$left" ] && podman rm -f -t 0 $left >/dev/null 2>&1 || true
}
trap cleanup EXIT
echo
echo "Open  http://127.0.0.1:$PORT  in a browser.   Ctrl-C stops the console."
echo "State dir: var/console (delete it, or use --reset, to start fresh)."
AEGIS_DEMO_MODE=1 .venv/bin/uvicorn aegis.console:app --host 127.0.0.1 --port "$PORT" --no-server-header --log-level warning &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' INT TERM
wait "$PID" || true
