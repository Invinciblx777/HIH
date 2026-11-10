#!/usr/bin/env bash
# AegisLab finale P3: start a hardened local llama.cpp model server for live real-model runs. Offline; nothing is downloaded.
#
#   scripts/start_model_server.sh --sandbox       llama-server in rootless Podman, --network none, reached over a UNIX socket
#   scripts/start_model_server.sh --host-process  llama-server as a host process on 127.0.0.1, random port
#   scripts/start_model_server.sh --stop RUNDIR   stop the server started with RUNDIR and delete RUNDIR (key included)
#
# Options: --model FILE.gguf  --server-dir DIR (holds llama-server)  --threads N (6)  --ctx N (4096)  --memory 3g
#          --expect-model-sha256 HEX  --expect-server-sha256 HEX   (refuse to start when a file differs)
# Defaults: AEGIS_MODELS_DIR, else <repo>/../../../_models, with qwen2.5-0.5b-instruct-q4_k_m.gguf and llama.cpp-b11819.
#
# Prints the run directory (mode 0700, under $XDG_RUNTIME_DIR) on the last line of stdout. It holds:
#   key        the API key, mode 0600, passed with --api-key-file (never on a command line, never in the environment)
#   model.env  AEGIS_MODEL_* settings for the console / broker (mode 0600; holds the key FILE path, not the key)
#   launch.json  flags, sha256 of model, server binary and (sandbox) libgomp, container name or pid
#   sock/llama.sock (sandbox only)  the server's only endpoint; the directory is 0700 and owned by this user, with one ACL
#              entry for the container's mapped UID; the socket itself belongs to that UID (AEGIS_MODEL_UNIX_SOCKET_OWNER_UID)
#   srvkey (sandbox only)  the server's own copy of the key, owned by the container's mapped UID (podman unshare chown), 0400
#
# Finale P4 (F4): the sandboxed server runs with --userns auto --user 900:900, i.e. as a subordinate host UID of its own, never
# as this user (who owns var/keys/broker_ed25519.pem and RUN/key). The launcher checks after start that the server process's
# host UID differs from this user's. libgomp (the image has none) is a vendored, verified copy: _models/libgomp-16.2.1-3.fc45/
# libgomp.so.1, sha256 pinned below (LIBGOMP_SHA256, override the file with AEGIS_LIBGOMP); a different file is refused.
#
# Cross-request state, as far as this llama.cpp build (b11819) lets a launcher close it (see THREAT_MODEL.md section 9):
#   --no-cache-prompt       server DEFAULT for cache_prompt becomes false. NOT a lock: a request that sends cache_prompt=true
#                           still reuses the slot's KV prefix (measured). The broker refuses to send true (aegis/model_client.py)
#                           and, in --sandbox mode, the broker is the only process that can reach the socket.
#   --cache-ram 0           host-RAM prompt cache (copies of earlier prompts' KV kept across slots) off
#   --no-cache-idle-slots   idle slots are not saved into that cache
#   --no-kv-unified -np 1   one slot with its own KV buffer, no buffer shared between sequences
#   --ctx-checkpoints 0     no per-slot context checkpoints kept
#   --cache-reuse 0         no KV-shift reuse of cached chunks
#   --no-slots              GET /slots (slot monitoring, shows prompts and parameters) returns 501
#   (no --slot-save-path)   slot save / restore to disk disabled: POST /slots/N?action=save returns 501
#   (no --props)            POST /props (change global settings) returns 501. GET /props cannot be turned off in this build;
#                           it needs the key and shows generation defaults and the model path, no prompt text
#   (no --metrics)          /metrics returns 501
#   --no-webui --no-agent --offline   no web UI, no built-in tools or MCP proxy, no model download
#   (no --log-prompts-dir)  prompts are not logged to disk
# Not closable from outside the server: the slot's live KV cells between requests (the next request overwrites them), CPU
# caches and memory-bandwidth contention, and timing.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
MODE=""; STOP=""; THREADS=6; CTX=4096; MEMORY=3g; EXPECT_MODEL=""; EXPECT_SERVER=""
MODELS="${AEGIS_MODELS_DIR:-$ROOT/../../../../_models}"   # <repo>/../../../_models, repo = aegislab/..
MODEL=""; SERVER_DIR=""
LIBGOMP_SHA256=2380ddc4427d9fde812406bfdbbf28f3cceecca77c4ad5fa88a7692b7cfade53   # Fedora libgomp-16.2.1-3.fc45, see PROVENANCE.txt
SANDBOX_UID=900; USERNS_SIZE=1024   # = aegis/userns.py SANDBOX_UID / USERNS_SIZE and the Containerfile USER
while [ $# -gt 0 ]; do
  case "$1" in
    --sandbox) MODE=sandbox ;;
    --host-process) MODE=host ;;
    --stop) STOP="${2:?--stop needs the run directory}"; shift ;;
    --model) MODEL="${2:?}"; shift ;;
    --server-dir) SERVER_DIR="${2:?}"; shift ;;
    --threads) THREADS="${2:?}"; shift ;;
    --ctx) CTX="${2:?}"; shift ;;
    --memory) MEMORY="${2:?}"; shift ;;
    --expect-model-sha256) EXPECT_MODEL="${2:?}"; shift ;;
    --expect-server-sha256) EXPECT_SERVER="${2:?}"; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
# Every die after the run directory exists removes it (it holds the API key); before finale P4 a refusal there left it behind
# (the ERR trap does not fire on an explicit exit). All such refusals happen before launch.json is written.
die() { echo "start_model_server: $*" >&2; [ -n "${RUN:-}" ] && [ -d "$RUN" ] && rm -rf -- "$RUN"; exit 1; }

if [ -n "$STOP" ]; then
  [ -f "$STOP/launch.json" ] || die "$STOP is not a model-server run directory"
  case "$(cd "$STOP" && pwd)" in "${XDG_RUNTIME_DIR:-/tmp}"/aegis-model.*) ;; *) die "refusing to remove $STOP: not an aegis-model run directory" ;; esac
  name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("container",""))' "$STOP/launch.json")
  pid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("pid",""))' "$STOP/launch.json")
  [ -n "$name" ] && podman rm -f -t 2 "$name" >/dev/null 2>&1 || true
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  rm -rf -- "$STOP"
  echo "stopped and removed $STOP"
  exit 0
fi

[ -n "$MODE" ] || die "choose --sandbox or --host-process (no default: the choice is printed on every label)"
[[ "$THREADS" =~ ^[0-9]+$ && "$CTX" =~ ^[0-9]+$ && "$MEMORY" =~ ^[0-9]+[mg]$ ]] || die "bad --threads/--ctx/--memory"
MODEL="${MODEL:-$MODELS/qwen2.5-0.5b-instruct-q4_k_m.gguf}"
SERVER_DIR="${SERVER_DIR:-$MODELS/llama.cpp-b11819/llama-b11819}"
[ -f "$MODEL" ] || die "model file not found: $MODEL (set --model or AEGIS_MODELS_DIR)"
[ -x "$SERVER_DIR/llama-server" ] || die "llama-server not found in $SERVER_DIR"
MODEL=$(cd "$(dirname "$MODEL")" && pwd)/$(basename "$MODEL"); SERVER_DIR=$(cd "$SERVER_DIR" && pwd)
MSHA=$(sha256sum "$MODEL" | cut -d' ' -f1); SSHA=$(sha256sum "$SERVER_DIR/llama-server" | cut -d' ' -f1)
[ -z "$EXPECT_MODEL" ] || [ "$EXPECT_MODEL" = "$MSHA" ] || die "model sha256 $MSHA differs from --expect-model-sha256"
[ -z "$EXPECT_SERVER" ] || [ "$EXPECT_SERVER" = "$SSHA" ] || die "llama-server sha256 $SSHA differs from --expect-server-sha256"
BUILD=$(LD_LIBRARY_PATH="$SERVER_DIR" "$SERVER_DIR/llama-server" --version 2>&1 | sed -n 's/.*(build \([0-9]*\).*/\1/p' | head -1)
SERVER_LABEL="llama.cpp CPU b${BUILD:-unknown}"

umask 077
RUN=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/aegis-model.XXXXXX")
trap 'rm -rf -- "$RUN"' ERR
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$RUN/key"
chmod 600 "$RUN/key"
FLAGS=(-m /models/model.gguf -c "$CTX" -np 1 -t "$THREADS" --threads-http 4 -a local -to 120
       --no-webui --no-agent --offline --api-key-file /run/aegis-key/key
       --no-cache-prompt --cache-ram 0 --no-cache-idle-slots --no-kv-unified --ctx-checkpoints 0 --cache-reuse 0 --no-context-shift
       --no-slots --cors-origins localhost --no-cors-credentials)

wait_health() {  # $1: curl transport args
  local i
  for i in $(seq 1 240); do
    if curl -sf --max-time 2 "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  return 1
}

if [ "$MODE" = sandbox ]; then
  command -v podman >/dev/null || die "podman not found"
  podman image exists localhost/aegislab-sandbox:0.1 || die "sandbox image localhost/aegislab-sandbox:0.1 missing (scripts/start_prototype.sh builds it)"
  GOMP="${AEGIS_LIBGOMP:-$MODELS/libgomp-16.2.1-3.fc45/libgomp.so.1}"
  [ -f "$GOMP" ] || die "vendored libgomp not found: $GOMP (llama-server needs it; the sandbox image has none; see PROVENANCE.txt)"
  GSHA=$(sha256sum "$GOMP" | cut -d' ' -f1)
  [ "$GSHA" = "$LIBGOMP_SHA256" ] || die "libgomp sha256 $GSHA differs from the pinned $LIBGOMP_SHA256 (refusing a changed library)"
  mkdir -m 700 "$RUN/sock"
  cp "$RUN/key" "$RUN/srvkey"
  NAME="aegis-model-server-$(basename "$RUN" | cut -d. -f2 | tr 'A-Z' 'a-z')"
  USERNS=(python3 "$ROOT/aegis/userns.py")
  PODMAN=(podman create --rm --name "$NAME" --label aegislab=1 --label aegislab-model-server=1
          --network none --read-only --tmpfs /tmp:rw,size=16m --cap-drop ALL --security-opt no-new-privileges
          --userns "auto:size=$USERNS_SIZE" --user "$SANDBOX_UID:$SANDBOX_UID" --umask 0000
          --pids-limit 64 --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$THREADS"
          -v "$SERVER_DIR:/opt/llama:ro,Z" -v "$GOMP:/opt/hostlib/libgomp.so.1:ro,Z" -v "$MODEL:/models/model.gguf:ro,Z"
          -v "$RUN/srvkey:/run/aegis-key/key:ro,Z" -v "$RUN/sock:/run/aegis-model:Z"
          -e LD_LIBRARY_PATH=/opt/llama:/opt/hostlib --entrypoint /opt/llama/llama-server localhost/aegislab-sandbox:0.1)
  "${PODMAN[@]}" "${FLAGS[@]}" --host /run/aegis-model/llama.sock >/dev/null || die "podman create failed"
  # The container's UID is known only now. The socket directory stays this user's (0700) with ONE ACL entry for that UID; the
  # server's key copy is chowned to it inside the rootless namespace and made 0400. --umask 0000 makes the socket connectable by
  # this user, who can reach it only through the private directory. Nothing else is granted.
  SUB=$("${USERNS[@]}" host-uid "$NAME") && INNER=$("${USERNS[@]}" inner-uid "$NAME") \
    && podman unshare chown "$INNER:$INNER" "$RUN/srvkey" && podman unshare chmod 0400 "$RUN/srvkey" \
    && "${USERNS[@]}" grant "$RUN/sock" "$SUB" rwx \
    || { podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "could not map the container UID or grant it its socket directory"; }
  podman start "$NAME" >/dev/null || { podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "podman start failed"; }
  SOCK="$RUN/sock/llama.sock"
  wait_health --unix-socket "$SOCK" http://localhost/health || { podman logs "$NAME" 2>&1 | tail -20 >&2; podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "server did not become healthy"; }
  NET=$(podman inspect "$NAME" --format '{{.HostConfig.NetworkMode}}')
  [ "$NET" = none ] || { podman rm -f -t 0 "$NAME" >/dev/null; die "container network mode is $NET, not none"; }
  PUID=$(awk '/^Uid:/ {print $2}' "/proc/$(podman inspect "$NAME" --format '{{.State.Pid}}')/status")
  [ "$PUID" = "$SUB" ] && [ "$PUID" != "$(id -u)" ] \
    || { podman rm -f -t 0 "$NAME" >/dev/null; die "server process runs as host UID $PUID (expected the mapped $SUB, never $(id -u))"; }
  cat > "$RUN/model.env" <<EOF
AEGIS_MODEL_BACKEND='openai_compatible'
AEGIS_MODEL_BASE_URL='http://localhost/v1'
AEGIS_MODEL_UNIX_SOCKET='$SOCK'
AEGIS_MODEL_UNIX_SOCKET_OWNER_UID='$SUB'
AEGIS_MODEL_NAME='local'
AEGIS_MODEL_API_KEY_FILE='$RUN/key'
AEGIS_MODEL_FILE_NAME='$(basename "$MODEL")'
AEGIS_MODEL_FILE_SHA256='$MSHA'
AEGIS_MODEL_SERVER='$SERVER_LABEL'
AEGIS_MODEL_SERVER_ISOLATION='rootless-podman-network-none'
EOF
  python3 - "$RUN/launch.json" "$NAME" "$MODEL" "$MSHA" "$SSHA" "$GSHA" "$SERVER_LABEL" "${PODMAN[*]} ${FLAGS[*]} --host /run/aegis-model/llama.sock" "$SUB" "$(id -u)" <<'PY'
import json, sys
f, name, model, msha, ssha, gsha, label, cmd, sub, me = sys.argv[1:]
json.dump({"mode": "sandbox", "container": name, "model_file": model.rsplit("/", 1)[1], "model_sha256": msha, "server_binary_sha256": ssha,
           "libgomp_sha256": gsha, "inference_server": label, "transport": "unix_socket", "network": "none",
           "userns": "auto", "server_process_host_uid": int(sub), "launcher_uid": int(me),
           "command": cmd.replace("/run/aegis-key/key", "<keyfile>")}, open(f, "w"), indent=2)
PY
else
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  HFLAGS=("${FLAGS[@]}")
  for i in "${!HFLAGS[@]}"; do
    [ "${HFLAGS[$i]}" = /models/model.gguf ] && HFLAGS[$i]="$MODEL"
    [ "${HFLAGS[$i]}" = /run/aegis-key/key ] && HFLAGS[$i]="$RUN/key"
  done
  LD_LIBRARY_PATH="$SERVER_DIR" nohup "$SERVER_DIR/llama-server" "${HFLAGS[@]}" --host 127.0.0.1 --port "$PORT" > "$RUN/server.log" 2>&1 &
  PID=$!
  wait_health "http://127.0.0.1:$PORT/health" || { tail -20 "$RUN/server.log" >&2; kill "$PID" 2>/dev/null; die "server did not become healthy"; }
  cat > "$RUN/model.env" <<EOF
AEGIS_MODEL_BACKEND='openai_compatible'
AEGIS_MODEL_BASE_URL='http://127.0.0.1:$PORT/v1'
AEGIS_MODEL_NAME='local'
AEGIS_MODEL_API_KEY_FILE='$RUN/key'
AEGIS_MODEL_FILE_NAME='$(basename "$MODEL")'
AEGIS_MODEL_FILE_SHA256='$MSHA'
AEGIS_MODEL_SERVER='$SERVER_LABEL'
AEGIS_MODEL_SERVER_ISOLATION='host-process'
EOF
  python3 - "$RUN/launch.json" "$PID" "$MODEL" "$MSHA" "$SSHA" "$SERVER_LABEL" "$PORT" "${HFLAGS[*]}" <<'PY'
import json, sys
f, pid, model, msha, ssha, label, port, cmd = sys.argv[1:]
json.dump({"mode": "host-process", "pid": int(pid), "model_file": model.rsplit("/", 1)[1], "model_sha256": msha, "server_binary_sha256": ssha,
           "inference_server": label, "transport": "tcp", "bind": "127.0.0.1:%s" % port, "command": cmd}, open(f, "w"), indent=2)
PY
fi
chmod 600 "$RUN/model.env" "$RUN/launch.json"
trap - ERR
echo "model server up: $SERVER_LABEL, $(basename "$MODEL") sha256 ${MSHA:0:12}…, mode $MODE" >&2
echo "$RUN"
