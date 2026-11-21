#!/usr/bin/env bash
# Stage launcher: the real-model console with the playground (Qwen3Guard, "Try a jailbreak (live)", Outside-In / TinyFish card),
# with budgets raised for this laptop's slower CPU (see scripts/stage/sitecustomize.py). Same options as
# scripts/start_real_model_console.sh (e.g. --reset); --playground is always on.
#   AEGIS_STAGE_DEADLINE_MS (default 10000)   AEGIS_STAGE_GUARD_TIMEOUT_MS (default 4000)
set -Eeuo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/scripts/stage${PYTHONPATH:+:$PYTHONPATH}" AEGIS_STAGE_SLOW_CPU=1
exec bash scripts/start_real_model_console.sh --playground "$@"
