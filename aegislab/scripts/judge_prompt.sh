#!/usr/bin/env bash
# Run a judge's own prompt as a red attack against the LIVE real model, through the full pipeline. See scripts/judge_prompt.py.
#   scripts/judge_prompt.sh                      interactive
#   scripts/judge_prompt.sh "prompt" [...]       one-shot
#   options: --defence sample|none  --leak-gateway  --long
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || { echo "no .venv yet: run scripts/quickstart.sh first" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman not found (see README)" >&2; exit 1; }
unset AEGIS_DEMO_MODE
exec .venv/bin/python scripts/judge_prompt.py "$@"
