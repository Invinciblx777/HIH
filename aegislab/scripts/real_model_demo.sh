#!/usr/bin/env bash
# LIVE REAL MODEL demo for the finale stage (offline, about 2 minutes, fresh state in a temporary directory).
#   scripts/real_model_demo.sh                  model server in rootless Podman (--network none, UNIX socket)
#   scripts/real_model_demo.sh --host-process   model server as a host process on 127.0.0.1
#   scripts/real_model_demo.sh --record F.json  also write the transcript and per-check results
# Needs the local model files (AEGIS_MODELS_DIR, default <repo>/../../../_models) and the sandbox image. Exit 0 only if every
# check passes. judge_demo.sh (stub model, precomputed real-model figures) is unchanged.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || { echo "no .venv yet: run scripts/start_prototype.sh once first" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman not found (see README)" >&2; exit 1; }
exec .venv/bin/python scripts/real_model_demo.py "$@"
