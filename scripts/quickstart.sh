#!/usr/bin/env bash
# One-command local start: venv, deps, sandbox image, tests, DEMO-001, web console on :8400.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt

podman pull -q docker.io/library/python:3.12-slim >/dev/null

pytest -q tests
python scripts/demo_run.py DEMO-001 >/dev/null
echo "DEMO-001 released. Console: http://127.0.0.1:8400"

AEGIS_DEMO_MODE=1 exec uvicorn aegis.api:app --host 127.0.0.1 --port 8400
