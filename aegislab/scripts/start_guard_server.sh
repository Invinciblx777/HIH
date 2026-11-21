#!/usr/bin/env bash
# AegisLab finale P16 (part A): start the Qwen3Guard blue-team guard as its OWN sandboxed llama.cpp server. Offline; nothing is
# downloaded. OFF unless you run this script and export the guard.env it writes (AEGIS_GUARD_RUNDIR); without that, every
# run uses sandbox/defence_runner.py exactly as at the tag aegislab-finale.
#
#   scripts/start_guard_server.sh               guard llama-server in rootless Podman, --network none, own UNIX socket
#   scripts/start_guard_server.sh --stop RUNDIR stop that server and delete RUNDIR (key included)
#
# Options: --model FILE.gguf  --server-dir DIR  --threads N (6)  --ctx N (4096, two slots of 2048)  --memory 2g  --expect-model-sha256 HEX
# Defaults: AEGIS_MODELS_DIR, else <repo>/../../../_models, with qwen3guard/Qwen3Guard-Gen-0.6B-Q8_0.gguf and llama.cpp-b11819.
#
# Same hardening as scripts/start_model_server.sh --sandbox (which this script leaves untouched): rootless Podman, --network none,
# --read-only, --cap-drop ALL, no-new-privileges, --userns auto --user 900:900 (a subordinate host UID of its own), read-only
# weights, API key in a file, cross-request caches off. Separate from the client model in every way that matters here:
#   * its own container, process and KV cache (a different llama-server; nothing shared with aegis-model-server-*);
#   * its own run directory ($XDG_RUNTIME_DIR/aegis-guard.*) and socket (sock/guard.sock), never the model's llama.sock;
#   * its own weights: only this container mounts the guard GGUF, and it never mounts the client model;
#   * label aegislab-guard-server=1 and NOT aegislab=1, so lab clean-ups and leftover checks neither kill nor count it.
# Prompt cache: the server default is --no-cache-prompt, as for the model. Two slots (-np 2, --no-kv-unified): slot 0 for prompt
# moderation, slot 1 for response moderation. guard/guard_runner.py resets its slot to the bare policy template before every
# call and then asks for cache_prompt, so a call reuses the template's KV and never an earlier text's (measured: cache_n is the
# template length on every call; tests/test_finale_p16_guard.py).
# Who reaches the socket: this user (to hand it to the broker) and, per run, the defence runner's container, which aegis/runtime.py
# grants on the socket directory only when AEGIS_GUARD_RUNDIR is set. Red and the model worker never get that mount.
#
# Prints the run directory (mode 0700) on the last line of stdout. It holds key (0600), srvkey (container's copy, 0400),
# sock/guard.sock, launch.json and guard.env (AEGIS_GUARD_* for the console / broker; holds file paths, never the key).
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
STOP=""; THREADS=6; CTX=4096; MEMORY=2g; EXPECT_MODEL=""
MODELS="${AEGIS_MODELS_DIR:-$ROOT/../../../../_models}"
MODEL=""; SERVER_DIR=""
LIBGOMP_SHA256=2380ddc4427d9fde812406bfdbbf28f3cceecca77c4ad5fa88a7692b7cfade53   # = scripts/start_model_server.sh
SANDBOX_UID=900; USERNS_SIZE=1024
while [ $# -gt 0 ]; do
  case "$1" in
    --stop) STOP="${2:?--stop needs the run directory}"; shift ;;
    --model) MODEL="${2:?}"; shift ;;
    --server-dir) SERVER_DIR="${2:?}"; shift ;;
    --threads) THREADS="${2:?}"; shift ;;
    --ctx) CTX="${2:?}"; shift ;;
    --memory) MEMORY="${2:?}"; shift ;;
    --expect-model-sha256) EXPECT_MODEL="${2:?}"; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
die() { echo "start_guard_server: $*" >&2; [ -n "${RUN:-}" ] && [ -d "$RUN" ] && rm -rf -- "$RUN"; exit 1; }

if [ -n "$STOP" ]; then
  [ -f "$STOP/launch.json" ] || die "$STOP is not a guard-server run directory"
  case "$(cd "$STOP" && pwd)" in "${XDG_RUNTIME_DIR:-/tmp}"/aegis-guard.*) ;; *) die "refusing to remove $STOP: not an aegis-guard run directory" ;; esac
  name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("container",""))' "$STOP/launch.json")
  [ -n "$name" ] && podman rm -f -t 2 "$name" >/dev/null 2>&1 || true
  podman unshare rm -rf -- "$STOP" 2>/dev/null || rm -rf -- "$STOP"
  echo "stopped and removed $STOP"
  exit 0
fi

[[ "$THREADS" =~ ^[0-9]+$ && "$CTX" =~ ^[0-9]+$ && "$MEMORY" =~ ^[0-9]+[mg]$ ]] || die "bad --threads/--ctx/--memory"
MODEL="${MODEL:-$MODELS/qwen3guard/Qwen3Guard-Gen-0.6B-Q8_0.gguf}"
SERVER_DIR="${SERVER_DIR:-$MODELS/llama.cpp-b11819/llama-b11819}"
[ -f "$MODEL" ] || die "guard model not found: $MODEL (set --model or AEGIS_MODELS_DIR)"
[ -x "$SERVER_DIR/llama-server" ] || die "llama-server not found in $SERVER_DIR"
MODEL=$(cd "$(dirname "$MODEL")" && pwd)/$(basename "$MODEL"); SERVER_DIR=$(cd "$SERVER_DIR" && pwd)
MSHA=$(sha256sum "$MODEL" | cut -d' ' -f1); SSHA=$(sha256sum "$SERVER_DIR/llama-server" | cut -d' ' -f1)
[ -z "$EXPECT_MODEL" ] || [ "$EXPECT_MODEL" = "$MSHA" ] || die "guard model sha256 $MSHA differs from --expect-model-sha256"
BUILD=$(LD_LIBRARY_PATH="$SERVER_DIR" "$SERVER_DIR/llama-server" --version 2>&1 | sed -n 's/.*(build \([0-9]*\).*/\1/p' | head -1)
SERVER_LABEL="llama.cpp CPU b${BUILD:-unknown}"
command -v podman >/dev/null || die "podman not found"
podman image exists localhost/aegislab-sandbox:0.1 || die "sandbox image localhost/aegislab-sandbox:0.1 missing (scripts/start_prototype.sh builds it)"
GOMP="${AEGIS_LIBGOMP:-$MODELS/libgomp-16.2.1-3.fc45/libgomp.so.1}"
[ -f "$GOMP" ] || die "vendored libgomp not found: $GOMP"
GSHA=$(sha256sum "$GOMP" | cut -d' ' -f1)
[ "$GSHA" = "$LIBGOMP_SHA256" ] || die "libgomp sha256 $GSHA differs from the pinned $LIBGOMP_SHA256"

umask 077
RUN=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/aegis-guard.XXXXXX")
trap 'rm -rf -- "$RUN"' ERR
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > "$RUN/key"
chmod 600 "$RUN/key"
mkdir -m 700 "$RUN/sock"
cp "$RUN/key" "$RUN/srvkey"
NAME="aegis-guard-server-$(basename "$RUN" | cut -d. -f2 | tr 'A-Z' 'a-z')"
FLAGS=(-m /models/guard.gguf -c "$CTX" -np 2 -t "$THREADS" -tb "$THREADS" --threads-http 2 -a guard -to 30
       --no-webui --no-agent --offline --api-key-file /run/aegis-key/key
       --no-cache-prompt --cache-ram 0 --no-cache-idle-slots --no-kv-unified --ctx-checkpoints 0 --cache-reuse 0 --no-context-shift
       --no-slots --cors-origins localhost --no-cors-credentials)
USERNS=(python3 "$ROOT/aegis/userns.py")
PODMAN=(podman create --rm --name "$NAME" --label aegislab-guard-server=1
        --network none --read-only --tmpfs /tmp:rw,size=16m --cap-drop ALL --security-opt no-new-privileges
        --userns "auto:size=$USERNS_SIZE" --user "$SANDBOX_UID:$SANDBOX_UID" --umask 0000
        --pids-limit 64 --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$THREADS"
        -v "$SERVER_DIR:/opt/llama:ro,Z" -v "$GOMP:/opt/hostlib/libgomp.so.1:ro,Z" -v "$MODEL:/models/guard.gguf:ro,Z"
        -v "$RUN/srvkey:/run/aegis-key/key:ro,Z" -v "$RUN/sock:/run/aegis-guard:Z"
        -e LD_LIBRARY_PATH=/opt/llama:/opt/hostlib --entrypoint /opt/llama/llama-server localhost/aegislab-sandbox:0.1)
"${PODMAN[@]}" "${FLAGS[@]}" --host /run/aegis-guard/guard.sock >/dev/null || die "podman create failed"
SUB=$("${USERNS[@]}" host-uid "$NAME") && INNER=$("${USERNS[@]}" inner-uid "$NAME") \
  && podman unshare chown "$INNER:$INNER" "$RUN/srvkey" && podman unshare chmod 0400 "$RUN/srvkey" \
  && "${USERNS[@]}" grant "$RUN/sock" "$SUB" rwx \
  || { podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "could not map the container UID or grant it its socket directory"; }
podman start "$NAME" >/dev/null || { podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "podman start failed"; }
SOCK="$RUN/sock/guard.sock"
ok=0
for i in $(seq 1 240); do curl -sf --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 && { ok=1; break; }; sleep 0.25; done
[ "$ok" = 1 ] || { podman logs "$NAME" 2>&1 | tail -20 >&2; podman rm -f -t 0 "$NAME" >/dev/null 2>&1; die "guard server did not become healthy"; }
NET=$(podman inspect "$NAME" --format '{{.HostConfig.NetworkMode}}')
[ "$NET" = none ] || { podman rm -f -t 0 "$NAME" >/dev/null; die "container network mode is $NET, not none"; }
PUID=$(awk '/^Uid:/ {print $2}' "/proc/$(podman inspect "$NAME" --format '{{.State.Pid}}')/status")
[ "$PUID" = "$SUB" ] && [ "$PUID" != "$(id -u)" ] \
  || { podman rm -f -t 0 "$NAME" >/dev/null; die "guard process runs as host UID $PUID (expected the mapped $SUB, never $(id -u))"; }
cat > "$RUN/guard.env" <<EOF
AEGIS_GUARD_RUNDIR='$RUN'
AEGIS_GUARD_MODEL_FILE_NAME='$(basename "$MODEL")'
AEGIS_GUARD_MODEL_FILE_SHA256='$MSHA'
AEGIS_GUARD_SERVER='$SERVER_LABEL'
EOF
python3 - "$RUN/launch.json" "$NAME" "$MODEL" "$MSHA" "$SSHA" "$GSHA" "$SERVER_LABEL" "${PODMAN[*]} ${FLAGS[*]} --host /run/aegis-guard/guard.sock" "$SUB" "$(id -u)" <<'PY'
import json, sys
f, name, model, msha, ssha, gsha, label, cmd, sub, me = sys.argv[1:]
json.dump({"mode": "sandbox", "role": "guard", "container": name, "model_file": model.rsplit("/", 1)[1], "model_sha256": msha,
           "server_binary_sha256": ssha, "libgomp_sha256": gsha, "inference_server": label, "transport": "unix_socket",
           "network": "none", "userns": "auto", "server_process_host_uid": int(sub), "launcher_uid": int(me),
           "command": cmd.replace("/run/aegis-key/key", "<keyfile>")}, open(f, "w"), indent=2)
PY
chmod 600 "$RUN/guard.env" "$RUN/launch.json"
trap - ERR
echo "guard server up: $SERVER_LABEL, $(basename "$MODEL") sha256 ${MSHA:0:12}…, container $NAME" >&2
echo "$RUN"
