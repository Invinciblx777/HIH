#!/usr/bin/env bash
# Finale P6 task 3: the Podman-dependent gates that release_gates.sh cannot run, as one script for the GitHub ubuntu-24.04
# runner (.github/workflows/live-gates.yml) and for any Linux host with rootless Podman.
#
#   tools/ci/live_gates.sh --out DIR                    environment report, image build, pytest -m podman, the live browser
#                                                       tests, judge_demo.sh, security_demo.sh, F4 userns proof (stub model)
#   tools/ci/live_gates.sh --out DIR --real-model M     also real_model_demo.sh and the F4 proof with the sandboxed model server;
#                                                       M is a _models directory (see .github/workflows/live-gates.yml)
#
# Every gate is reported PASS or FAIL with its exit code and log. Nothing is skipped silently:
#   - pytest -m podman fails this script if ANY test is skipped or deselected (the Podman tests skip themselves when the
#     image is missing; on this gate that is a failure, not a pass);
#   - the F4 proof must report classification "pass";
#   - a missing prerequisite (rootless Podman, subordinate UIDs, cgroup controllers, POSIX ACLs) is printed by the
#     environment report and then fails the gate that needs it.
# It lives in tools/, outside the MANIFEST-pinned folders and outside code_revision's tree, so adding it changes neither.
set -Euo pipefail
cd "$(dirname "$0")/../../aegislab"
OUT=""; MODELS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?}"; shift ;;
    --real-model) MODELS="${2:?}"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
OUT=${OUT:-$(mktemp -d -t aegis-live-XXXXXX)}; mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
export PYTHONDONTWRITEBYTECODE=1
unset AEGIS_DEMO_MODE AEGIS_CONSOLE_LAUNCH_CODE
PY=.venv/bin/python
[ -x "$PY" ] || { echo "FAIL  .venv missing (python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -c constraints.txt)"; exit 1; }
: > "$OUT/summary.txt"; FAILS=0
gate() {
  local name=$1; shift; local log="$OUT/$name.log" t0=$SECONDS rc
  "$@" > "$log" 2>&1; rc=$?
  if [ $rc = 0 ]; then
    printf 'PASS  %-22s exit 0  %4ds  %s\n' "$name" $((SECONDS - t0)) "$(tail -n 1 "$log" | cut -c1-100)" | tee -a "$OUT/summary.txt"
  else
    FAILS=$((FAILS + 1))
    printf 'FAIL  %-22s exit %s  %4ds  see %s\n' "$name" "$rc" $((SECONDS - t0)) "$log" | tee -a "$OUT/summary.txt"
    tail -n 25 "$log" | sed 's/^/      | /'
  fi
}

env_report() {
  set +e
  echo "kernel: $(uname -r)"; . /etc/os-release 2>/dev/null; echo "os: ${PRETTY_NAME:-unknown}"
  echo "user: $(id -un) uid=$(id -u)"; echo "nproc: $(nproc)"; free -m | sed -n 2p
  echo "podman: $(podman --version 2>&1)"
  echo "rootless: $(podman info --format '{{.Host.Security.Rootless}}' 2>&1)"
  echo "oci runtime: $(podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}' 2>&1 | head -1)"
  echo "cgroup manager: $(podman info --format '{{.Host.CgroupManager}}' 2>&1) version: $(podman info --format '{{.Host.CgroupsVersion}}' 2>&1)"
  echo "cgroup controllers for this user: $(podman info --format '{{.Host.CgroupControllers}}' 2>&1)"
  echo "subuid: $(grep -E "^($(id -un)|$(id -u)):" /etc/subuid 2>&1 || echo NONE)"
  echo "subgid: $(grep -E "^($(id -un)|$(id -u)):" /etc/subgid 2>&1 || echo NONE)"
  echo "apparmor_restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
  echo "XDG_RUNTIME_DIR: ${XDG_RUNTIME_DIR:-unset}"
  "$PY" - <<'PY'
import os, tempfile
from aegis import userns
d = tempfile.mkdtemp(dir=".")
try:
    userns.grant(d, 4242424, "r-x")
    ok = 4242424 in userns.named_users(d)
    print("posix ACL on the work tree:", "yes" if ok else "NO (grant did not stick)")
except OSError as e:
    print("posix ACL on the work tree: NO (%s)" % e)
finally:
    os.rmdir(d)
print("sub-UID ranges (aegis.userns):", userns.subid_ranges("uid"))
PY
  return 0
}
env_report | tee "$OUT/00_environment.txt"

checked_pytest() {  # pytest -m podman; every selected test must PASS: any skip/deselect/xfail is a failure here
  # tests/browser is run by run_browser_tests.sh --live below (it needs .venv-browser); in .venv those 2 tests skip by design
  "$PY" -m pytest -q -p no:cacheprovider -m podman -rA tests --ignore=tests/browser | tee "$OUT/pytest_podman_raw.txt"
  local rc=${PIPESTATUS[0]}
  local last; last=$(tail -n 1 "$OUT/pytest_podman_raw.txt")
  if [ "$rc" != 0 ]; then return "$rc"; fi
  if echo "$last" | grep -Eq 'skipped|xfailed|xpassed|error'; then echo "NOT ALL PASSED: $last"; return 3; fi
  echo "$last" | grep -Eq '^=* *[0-9]+ passed' || { echo "no passing tests found: $last"; return 4; }
}

f4_proof() {  # AEGIS_VAR in a fresh scratch dir, as the proof's docstring requires
  local scratch; scratch=$(mktemp -d -t aegis-f4-XXXXXX)
  AEGIS_VAR="$scratch/var" "$PY" evaluation/p4_userns_proof.py --out-dir "$OUT/$1" --models "${2:-/nonexistent}"
  local rc=$?; rm -rf "$scratch"; return $rc
}

gate image "$PY" -c 'from aegis import runtime, store; print("sandbox image id:", runtime.build_image(store.ROOT))'
gate pytest-podman checked_pytest
gate browser-live bash scripts/run_browser_tests.sh --live --require --no-install --out "$OUT/browser"
gate judge-demo bash scripts/judge_demo.sh
gate security-demo bash scripts/security_demo.sh
gate f4-userns-proof f4_proof f4_stub
if [ -n "$MODELS" ]; then
  export AEGIS_MODELS_DIR="$MODELS"
  for i in 1 2 3; do gate real-model-demo-$i bash scripts/real_model_demo.sh; done
  gate f4-userns-proof-model f4_proof f4_model "$MODELS"
fi
podman ps -a --filter label=aegislab=1 --format '{{.Names}} {{.Status}}' > "$OUT/leftover_containers.txt"
echo "logs: $OUT"
[ "$FAILS" = 0 ] && echo "ALL LIVE GATES PASSED" || echo "$FAILS LIVE GATE(S) FAILED"
[ "$FAILS" = 0 ]
