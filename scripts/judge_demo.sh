#!/usr/bin/env bash
# Judge-facing PRESENTATION MODE demo (deterministic, local, offline, fresh state, a few seconds).
#   scripts/judge_demo.sh                 run the short path; exit 0 only if every check behaved as expected
#   scripts/judge_demo.sh --pause         wait for Enter between steps while presenting
#   scripts/judge_demo.sh --record F.json also write a timestamped transcript
# The original demo (34 checks, scripts/security_demo.sh) is unchanged. Step 6 prints PRECOMPUTED real-model results; no model runs here.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || { echo "no .venv yet: run scripts/quickstart.sh first" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman not found (see README)" >&2; exit 1; }
exec .venv/bin/python scripts/judge_demo.py "$@"
