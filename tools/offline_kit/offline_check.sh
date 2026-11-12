#!/usr/bin/env bash
# Prove the restored copy works with no network. Run it inside a network namespace with no route (`unshare -rn`) for the
# parts that need no Podman, and on the host with networking off for the Podman parts (see OFFLINE_KIT.md, "Proof").
#   bash offline_check.sh DEST_DIR OUT_DIR [--no-podman]
# Steps: 0 no network; 1 judge_demo.sh; 2 real_model_demo.sh; 3 real_model_console_check.py (Playwright); 4 the local public
# demo (AEGIS_PUBLIC_DEMO=1 through app.py on 127.0.0.1:8415): /api/lab/status, then public_demo_check.py --local.
set -uo pipefail
DEST=$(cd "${1:?DEST_DIR}" && pwd); OUT=${2:?OUT_DIR}; mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd); NOPOD=0; [ "${3:-}" = --no-podman ] && NOPOD=1
. "$DEST/kit.env"; cd "$DEST/HIH/aegislab"
: > "$OUT/summary.txt"; FAILS=0
gate() { local n=$1; shift; local t0=$SECONDS; "$@" > "$OUT/$n.log" 2>&1; local rc=$?
  printf '%s  %-26s exit %s  %4ss  %s\n' "$([ $rc = 0 ] && echo PASS || echo FAIL)" "$n" "$rc" $((SECONDS - t0)) "$(tail -n 1 "$OUT/$n.log" | cut -c1-100)" | tee -a "$OUT/summary.txt"
  [ $rc = 0 ] || FAILS=$((FAILS + 1)); }
no_network() {  # every one of these must FAIL for the run to count as offline
  local bad=0
  for h in pypi.org github.com huggingface.co aegislab-demo.onrender.com; do
    if curl -s -m 5 -o /dev/null "https://$h/"; then echo "REACHABLE: $h"; bad=1; else echo "unreachable: $h (curl exit $?)"; fi
  done
  ip -brief addr 2>/dev/null; ip route 2>/dev/null | sed 's/^/route: /'
  [ $bad = 0 ] && echo "offline confirmed"
  return $bad
}
public_demo() {
  local V; V=$(mktemp -d); AEGIS_VAR="$V/var" .venv/bin/uvicorn app:app --host 127.0.0.1 --port 8415 --log-level warning & local pid=$!
  for i in $(seq 1 40); do curl -s -m 1 -o /dev/null http://127.0.0.1:8415/api/lab/status && break; sleep 0.25; done
  curl -s http://127.0.0.1:8415/api/lab/status | python3 -c 'import json,sys; d=json.load(sys.stdin); print("public_demo=%s mode=%s" % (d["public_demo"], d["mode"])); sys.exit(0 if d["public_demo"] is True else 1)'
  local a=$?
  .venv-browser/bin/python ../tools/offline_kit/public_demo_check.py http://127.0.0.1:8415 "$OUT/public_demo_shots" --local; local b=$?
  kill -INT $pid; wait $pid 2>/dev/null; rm -rf "$V"
  [ $a = 0 ] && [ $b = 0 ]
}
gate 00_no_network no_network
if [ "$NOPOD" = 0 ]; then
  gate 01_judge_demo bash scripts/judge_demo.sh
  gate 02_real_model_demo bash scripts/real_model_demo.sh
  gate 03_real_model_console .venv-browser/bin/python scripts/real_model_console_check.py --shots "$OUT/console_shots"
fi
gate 04_local_public_demo public_demo
echo "$FAILS failed" | tee -a "$OUT/summary.txt"
[ "$FAILS" = 0 ]
