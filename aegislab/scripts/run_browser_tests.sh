#!/usr/bin/env bash
# Browser end-to-end tests with a pinned, reproducible set-up (Phase R3).
#
#   scripts/run_browser_tests.sh               container-free tests (tests/browser/test_console_browser_core.py)
#   scripts/run_browser_tests.sh --live        the live lab in real rootless containers (tests/browser/test_console_browser.py)
#   scripts/run_browser_tests.sh --all         both
#   options: --require     a missing dependency or runtime counts as a failure, not a skip (use this as a release gate)
#            --no-install  do not create virtualenvs or download Chromium; whatever is missing is reported, not fixed
#            --out DIR     where the JUnit XML and the summary go (default: a new temporary directory)
#
# Set-up it performs when needed: .venv (console, requirements.txt with constraints.txt), .venv-browser
# (requirements-browser.txt: Playwright 1.64.1) and Playwright's Chromium (cached in ~/.cache/ms-playwright).
# Every test is reported as PASS, FAIL, SKIPPED (dependency missing) or BLOCKED (runtime unavailable). A skipped or blocked
# security test is never counted as passed. Exit 0 only if nothing failed and, with --require, nothing was skipped or blocked.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
SEL=core; REQUIRE=0; INSTALL=1; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --live) SEL=live ;;
    --all) SEL=all ;;
    --require) REQUIRE=1 ;;
    --no-install) INSTALL=0 ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
OUT=${OUT:-$(mktemp -d -t aegis-browser-XXXXXX)}
mkdir -p "$OUT"
export PYTHONDONTWRITEBYTECODE=1
unset AEGIS_DEMO_MODE AEGIS_CONSOLE_LAUNCH_CODE

if [ "$INSTALL" = 1 ]; then
  if ! .venv/bin/python -c 'import fastapi, uvicorn, cryptography, httpx' 2>/dev/null; then
    [ -x .venv/bin/python ] || python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt -c constraints.txt
  fi
  if ! .venv-browser/bin/python -c 'import playwright, pytest' 2>/dev/null; then
    [ -x .venv-browser/bin/python ] || python3 -m venv .venv-browser
    .venv-browser/bin/pip install -q -r requirements-browser.txt
  fi
  .venv-browser/bin/playwright install chromium >/dev/null
fi
PY=.venv-browser/bin/python
[ -x "$PY" ] || PY=python3   # --no-install without the browser virtualenv: the modules report SKIPPED (dependency missing)

case "$SEL" in
  core) TESTS=(tests/browser/test_console_browser_core.py) ;;
  live) TESTS=(tests/browser/test_console_browser.py) ;;
  all)  TESTS=(tests/browser/test_console_browser_core.py tests/browser/test_console_browser.py) ;;
esac
if [ "$REQUIRE" = 1 ]; then export AEGIS_REQUIRE_BROWSER=1; [ "$SEL" = core ] || export AEGIS_REQUIRE_PODMAN=1; fi

echo "browser tests: ${TESTS[*]}  (python: $PY, results: $OUT)"
set +e
"$PY" -m pytest -q -rs -p no:cacheprovider --junitxml="$OUT/junit.xml" "${TESTS[@]}" 2>&1 | tee "$OUT/pytest.log"
RC=${PIPESTATUS[0]}
set -e
python3 - "$OUT/junit.xml" "$REQUIRE" "$RC" <<'PY' | tee "$OUT/summary.txt"
import sys, xml.etree.ElementTree as ET
path, require, rc = sys.argv[1], sys.argv[2] == "1", int(sys.argv[3])
try:
    cases = list(ET.parse(path).getroot().iter("testcase"))
except (OSError, ET.ParseError):
    print("FAIL  no JUnit result (pytest exit %d): see pytest.log" % rc); sys.exit(1)
counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0, "BLOCKED": 0}
for c in cases:
    name = "%s::%s" % (c.get("classname", "").split(".")[-1], c.get("name"))
    if c.find("failure") is not None or c.find("error") is not None:
        k, why = "FAIL", (c.find("failure") if c.find("failure") is not None else c.find("error")).get("message", "")[:160]
    elif c.find("skipped") is not None:
        why = c.find("skipped").get("message", "")
        k = "BLOCKED" if "BLOCKED" in why else "SKIPPED"
    else:
        k, why = "PASS", ""
    counts[k] += 1
    print("%-7s %s%s" % (k, name, ("  -- " + why.replace("\n", " ")[:200]) if why else ""))
print("summary: " + ", ".join("%s %d" % kv for kv in counts.items()) + " (pytest exit %d)" % rc)
bad = counts["FAIL"] or (rc not in (0, 5) and not counts["FAIL"]) or (require and (counts["SKIPPED"] or counts["BLOCKED"] or not cases))
print("verdict: " + ("FAIL" if bad else "PASS" if counts["PASS"] and not (counts["SKIPPED"] or counts["BLOCKED"]) else "INCOMPLETE (nothing failed; see SKIPPED/BLOCKED)"))
sys.exit(1 if bad else 0)
PY
