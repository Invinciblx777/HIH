#!/usr/bin/env bash
# Judge-facing security demonstration (deterministic, local, fresh state, nothing under evidence/ or var/ is touched).
#   scripts/security_demo.sh            run all steps, exit 0 only if every check behaved as expected
#   scripts/security_demo.sh --pause    wait for Enter between steps while presenting
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[ -x .venv/bin/python ] || { echo "no .venv yet: run scripts/quickstart.sh first" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman not found (see README)" >&2; exit 1; }
exec .venv/bin/python scripts/security_demo.py "$@"
