#!/usr/bin/env bash
# AegisLab finale: put the laptop back to a clean stage state between rehearsals or after a failure drill.
#   1. stop the consoles (stub 8400, real model 8410, local public demo 8415) with SIGINT, so each one cleans up after itself;
#   2. stop every sandboxed or host-process model server this user started (scripts/start_model_server.sh --stop RUNDIR);
#   3. remove the containers labelled aegislab=1 that are left (lab and model containers; nothing else is touched);
#   4. clear console and run state: aegislab/var/console, var/console-real and var/console-public. Never evidence/, never
#      var/keys, var/reviewer_vault or var/anchors (the operator's keys and the reviewer's retained copies);
#   5. print a fresh status (the preflight checks that matter here).
#   tools/venue/reset.sh            do it
#   tools/venue/reset.sh --dry-run  print what it would do
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd); APP="$REPO/aegislab"
# shellcheck disable=SC1091
. "$HERE/expected.env"
DRY=0; [ "${1:-}" = --dry-run ] && DRY=1
run() { echo "  \$ $*"; [ "$DRY" = 1 ] || "$@"; }

echo "1. consoles"
for p in $PORTS; do
  for pid in $(ss -Hltnp "sport = :$p" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    [ "$(stat -c %u "/proc/$pid" 2>/dev/null)" = "$(id -u)" ] || { echo "  port $p: pid $pid is not ours, left alone"; continue; }
    echo "  port $p: pid $pid $(tr '\0' ' ' < "/proc/$pid/cmdline" | cut -c1-80)"
    # the real-model launcher (parent of the console) traps INT and stops its model server; signal it first
    ppid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null)
    if [ -n "$ppid" ] && grep -qa start_real_model_console "/proc/$ppid/cmdline" 2>/dev/null; then run kill -INT "$ppid"; fi
    run kill -INT "$pid"
  done
done
[ "$DRY" = 1 ] || for i in $(seq 1 20); do
  busy=0; for p in $PORTS; do ss -Hltn "sport = :$p" | grep -q . && busy=1; done; [ $busy = 0 ] && break; sleep 0.5
done
[ "$DRY" = 1 ] || for p in $PORTS; do
  for pid in $(ss -Hltnp "sport = :$p" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    [ "$(stat -c %u "/proc/$pid" 2>/dev/null)" = "$(id -u)" ] && { echo "  port $p still held after 10 s: SIGTERM $pid"; kill -TERM "$pid"; }
  done
done

echo "2. model servers"
for d in "${XDG_RUNTIME_DIR:-/tmp}"/aegis-model.*; do
  [ -d "$d" ] || continue
  run bash "$APP/scripts/start_model_server.sh" --stop "$d"
done

echo "3. containers labelled aegislab=1"
for c in $(podman ps -a --filter label=aegislab=1 --format '{{.Names}}'); do run podman rm -f -t 2 "$c"; done

echo "4. console and run state"
for d in console console-real console-public; do
  [ -e "$APP/var/$d" ] && run rm -rf -- "${APP:?}/var/$d"
done

echo "5. status"
[ "$DRY" = 1 ] && exit 0
podman ps -a --filter label=aegislab=1 --format '   leftover: {{.Names}}' | grep . || echo "  no aegislab containers"
for p in $PORTS; do ss -Hltn "sport = :$p" | grep -q . && echo "  port $p: IN USE" || echo "  port $p: free"; done
ls -d "${XDG_RUNTIME_DIR:-/tmp}"/aegis-model.* 2>/dev/null | sed 's/^/  model run dir left: /' || echo "  no model server run directories"
echo "  var/: $(ls "$APP/var" | tr '\n' ' ')"
echo "Reset done. Next: tools/venue/preflight.sh"
