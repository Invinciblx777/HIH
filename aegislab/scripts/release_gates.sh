#!/usr/bin/env bash
# Container-free release gates (Phase R3): the checks that must pass before a commit is published. The same script runs
# locally and in .github/workflows/release-gates.yml, so a green workflow means exactly these checks ran and passed.
#
#   scripts/release_gates.sh                 every container-free gate below
#   scripts/release_gates.sh --with-browser  also the container-free browser tests (scripts/run_browser_tests.sh --require)
#   scripts/release_gates.sh --out DIR       logs and summary.txt go to DIR (default: a new temporary directory)
#
# Gates: Python syntax of every source file and import of the console; JavaScript syntax of the console UI (needs node);
# the test suite without the tests marked podman; check_claims.py; check_presentation.py; sha256sum -c MANIFEST.sha256;
# tools/publication_scan.py on the git index. Each is reported PASS, FAIL or SKIPPED (with the reason); a skipped gate is
# never reported as passed, and --strict turns any SKIPPED into a failure.
#
# Not covered here (needs rootless Podman and the sandbox image): pytest -m podman, scripts/judge_demo.sh,
# scripts/security_demo.sh, scripts/run_browser_tests.sh --live. Run those on the supported Fedora host before a release.
set -Euo pipefail
cd "$(dirname "$0")/.."
BROWSER=0; STRICT=0; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-browser) BROWSER=1 ;;
    --strict) STRICT=1 ;;
    --out) OUT="${2:?--out needs a directory}"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
OUT=${OUT:-$(mktemp -d -t aegis-gates-XXXXXX)}
mkdir -p "$OUT"
export PYTHONDONTWRITEBYTECODE=1
unset AEGIS_DEMO_MODE AEGIS_CONSOLE_LAUNCH_CODE
for k in $(env | sed -n 's/^\(AEGIS_MODEL[A-Z_]*\)=.*/\1/p'); do unset "$k"; done
PY=.venv/bin/python
[ -x "$PY" ] || { echo "FAIL  .venv missing: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -c constraints.txt"; exit 1; }
: > "$OUT/summary.txt"
FAILS=0; SKIPS=0

gate() {   # gate NAME COMMAND...  (runs the command, records PASS/FAIL with its exit code and log)
  local name=$1; shift
  local log="$OUT/$name.log" t0=$SECONDS rc
  "$@" > "$log" 2>&1; rc=$?
  if [ $rc = 0 ]; then
    printf 'PASS     %-22s exit 0  %3ds  %s\n' "$name" $((SECONDS - t0)) "$(tail -n 1 "$log" | cut -c1-90)" | tee -a "$OUT/summary.txt"
  else
    FAILS=$((FAILS + 1))
    printf 'FAIL     %-22s exit %s  %3ds  see %s\n' "$name" "$rc" $((SECONDS - t0)) "$log" | tee -a "$OUT/summary.txt"
    tail -n 15 "$log" | sed 's/^/         | /'
  fi
}
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIPPED  %-22s %s\n' "$1" "$2" | tee -a "$OUT/summary.txt"; }

gate python-syntax "$PY" -c '
import ast, pathlib, sys
files = [p for d in ("aegis", "evaluation", "scripts", "tests", "sandbox") for p in pathlib.Path(d).rglob("*.py")]
for p in files:
    ast.parse(p.read_text(), str(p))
import aegis.console, aegis.api, aegis.verify_cli
print("%d files parsed; aegis.console imports" % len(files))'
if command -v node >/dev/null; then
  gate js-syntax node --check web/console/console.js
else
  skip js-syntax "node is not installed"
fi
# P4D01 runs scripts/judge_demo.sh in a real container but is only skipped when podman is missing from PATH, not marked podman
# (its file is pinned by MANIFEST.sha256). It belongs to the Fedora integration gate, where the full suite runs it.
gate pytest-container-free "$PY" -m pytest -q -p no:cacheprovider -m "not podman" -rs \
  --deselect tests/test_phase4_presentation.py::test_P4D01_judge_demo_passes_and_labels_precomputed_evidence
gate check-claims "$PY" evaluation/check_claims.py
gate check-presentation "$PY" evaluation/check_presentation.py
gate manifest bash -c 'cd .. && sha256sum --quiet -c MANIFEST.sha256 && echo "MANIFEST.sha256: $(wc -l < MANIFEST.sha256) entries OK"'
if git -C .. rev-parse --git-dir >/dev/null 2>&1; then
  gate publication-scan python3 ../tools/publication_scan.py --repo ..
else
  skip publication-scan "not a git checkout"
fi
if [ "$BROWSER" = 1 ]; then
  gate browser-core bash scripts/run_browser_tests.sh --require --out "$OUT/browser"
else
  skip browser-core "not requested (--with-browser)"
fi

echo "summary: $FAILS failed, $SKIPS skipped  (logs: $OUT)" | tee -a "$OUT/summary.txt"
[ "$FAILS" = 0 ] || exit 1
[ "$STRICT" = 0 ] || [ "$SKIPS" = 0 ] || { echo "--strict: skipped gates count as failures"; exit 1; }
exit 0
