#!/usr/bin/env bash
# AegisLab finale P3: the prototype console with the REAL model live. Fully offline; nothing is downloaded or built.
#
#   scripts/start_real_model_console.sh                  model server in rootless Podman (--network none, UNIX socket)
#   scripts/start_real_model_console.sh --host-process   model server as a host process on 127.0.0.1 (random port)
#   scripts/start_real_model_console.sh --port 8410      console port (default 8410, so it never collides with the stub console)
#   scripts/start_real_model_console.sh --reset          delete this console's state directory (var/console-real) first
#   scripts/start_real_model_console.sh --link           a new launch link for the real-model console that is running
#   scripts/start_real_model_console.sh --any-model      do not insist on the Phase 3 model and server hashes
#
# 1. starts scripts/start_model_server.sh (hardened flags; the API key goes in a 0600 file) and waits until it answers;
# 2. starts the console on 127.0.0.1 with AEGIS_MODEL_BACKEND=openai_compatible and the server's settings, state in
#    var/console-real (separate from the stub console's var/console);
# 3. Ctrl-C stops the console, removes lab containers it left, stops the model server and deletes its key.
# The console labels every real-model run "REAL MODEL · LIVE" with the model file, its sha256 prefix, "llama.cpp CPU" and
# "loopback". There is no fallback to the stub: if the model server stops, a run fails closed and red gets the uniform refusal.
# scripts/start_prototype.sh (the stub console) is unchanged and still the default for every other demo.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PORT=8410; MODE=--sandbox; RESET=0; LINK=0; ANY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?--port needs a number}"; shift ;;
    --host-process) MODE=--host-process ;;
    --sandbox) MODE=--sandbox ;;
    --reset) RESET=1 ;;
    --link) LINK=1 ;;
    --any-model) ANY=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || { echo "--port must be a number between 1024 and 65535" >&2; exit 2; }
if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'; else G=; R=; N=; fi
ok()  { echo "  ${G}ok${N}    $*"; }
die() { echo "  ${R}fail${N}  $1" >&2; echo "        -> $2" >&2; exit 1; }

export AEGIS_VAR="$ROOT/var/console-real"
export PYTHONDONTWRITEBYTECODE=1
unset AEGIS_DEMO_MODE AEGIS_CONSOLE_LAUNCH_CODE AEGIS_PUBLIC_DEMO
for k in $(env | sed -n 's/^\(AEGIS_MODEL[A-Z_]*\)=.*/\1/p'); do unset "$k"; done   # only the launcher's settings below
unset AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE

if [ "$LINK" = 1 ]; then
  CODE=$(.venv/bin/python -c 'from aegis import lab_session; print(lab_session.issue())') || die "could not issue a launch code" "is the real-model console running?"
  echo "http://127.0.0.1:$PORT/session/start?code=$CODE"; exit 0
fi

echo "AegisLab console with the REAL model: prerequisites (offline)"
[ -x .venv/bin/python ] && .venv/bin/python -c 'import fastapi, uvicorn, cryptography, httpx' 2>/dev/null \
  || die ".venv with the requirements is missing" "run scripts/start_prototype.sh once with network access to create it"
ok "virtualenv .venv"
command -v podman >/dev/null && [ "$(timeout 20 podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)" = true ] \
  || die "rootless podman is not usable" "live runs need it; the stub console (scripts/start_prototype.sh) has a degraded mode, this one does not"
podman image exists localhost/aegislab-sandbox:0.1 || die "sandbox image localhost/aegislab-sandbox:0.1 missing" "run scripts/start_prototype.sh once to build it"
ok "podman $(podman --version | awk '{print $3}') rootless, sandbox image present"
.venv/bin/python - "$PORT" <<'PY' || die "port $PORT is already in use" "stop the other process or choose another port with --port"
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) else 1)
PY
ok "port $PORT free on 127.0.0.1"

EXPECT=()
[ "$ANY" = 1 ] || EXPECT=(--expect-model-sha256 74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
                          --expect-server-sha256 17d2573dede0314fe681f3c2c821a9a44818949e1073200292353efb21c426bb)
RUN=$(scripts/start_model_server.sh "$MODE" "${EXPECT[@]}") || die "the model server did not start" "see the message above; nothing falls back to the stub"
RUN=$(printf '%s\n' "$RUN" | tail -1)
cleanup() {
  local left
  left=$(podman ps -a --filter label=aegislab=1 --format '{{.Names}}' 2>/dev/null | grep -E '^aegis-(lab-[0-9]{3}-(red|blue|model)|lab-probe-[0-9a-f]{8})$' || true)
  [ -n "$left" ] && podman rm -f -t 0 $left >/dev/null 2>&1 || true
  scripts/start_model_server.sh --stop "$RUN" >/dev/null 2>&1 || true
}
trap cleanup EXIT
set -a; . "$RUN/model.env"; set +a
ok "model server: $AEGIS_MODEL_SERVER, $AEGIS_MODEL_FILE_NAME sha256 ${AEGIS_MODEL_FILE_SHA256:0:12}, $AEGIS_MODEL_SERVER_ISOLATION"
.venv/bin/python -c 'from aegis import model_client as mc; mc.OpenAICompatibleClient(mc.load_config()).ping()' \
  || die "the adapter cannot reach the model server" "nothing falls back to the stub"
ok "adapter reaches the model server"

[ "$RESET" = 1 ] && [ -d "$AEGIS_VAR" ] && { rm -rf -- "$AEGIS_VAR"; ok "reset: removed var/console-real"; }
mkdir -p "$AEGIS_VAR"
echo
echo "Mode: LIVE with the REAL model. Every lab run is answered by $AEGIS_MODEL_FILE_NAME on llama.cpp CPU, over loopback."
CODE=$(.venv/bin/python -c 'from aegis import lab_session; print(lab_session.issue())') || die "could not issue a launch code" "check write permission in var/console-real"
echo "Open this launch link in a browser on this machine (it starts the operator session):"
echo
echo "    http://127.0.0.1:$PORT/session/start?code=$CODE"
echo
echo "The link works once. Another one: scripts/start_real_model_console.sh --link$([ "$PORT" = 8410 ] || echo " --port $PORT")"
echo "Ctrl-C stops the console and the model server."
.venv/bin/uvicorn aegis.console:app --host 127.0.0.1 --port "$PORT" --no-server-header --log-level warning &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' INT TERM
wait "$PID" || true
