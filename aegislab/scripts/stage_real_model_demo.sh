#!/usr/bin/env bash
# real_model_demo.sh for the stage screen: identical run and exit code, minus the demo gateway's BrokenPipe tracebacks.
# Those tracebacks appear when the broker cuts a request off at its release deadline and closes the connection (the deadline
# policy working). evaluation/llm_common.py is hash-pinned by the evidence checks, so it is not edited; Python's socketserver
# prints each such traceback to stderr between two lines of 40 dashes, and this filter drops exactly those blocks.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
bash scripts/real_model_demo.sh "$@" 2> >(awk 'BEGIN { d = "----------------------------------------" }
  $0 == d { skip = !skip; next } !skip { print; fflush() }' >&2)
