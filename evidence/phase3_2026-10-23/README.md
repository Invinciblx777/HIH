# Phase 3 evidence: LLM-native isolation (23 Oct 2026)

Everything here was produced on one host (AMD Ryzen 7 7735HS, 16 threads, no GPU in use) against `llama.cpp` build 11819 (`llama-server`, CPU) and `qwen2.5-0.5b-instruct-q4_k_m.gguf` (sha256 `74a4da8c...`), bound to 127.0.0.1 with a random API key per server. Nothing was downloaded. All canaries, tokens and keys are synthetic.

## Layout

| Path | Content |
|---|---|
| `llm/INDEX.json` | One entry per experiment run (run id, classification, sha256 of its `result.json`). A later entry for the same experiment supersedes an earlier one; earlier runs stay on disk. |
| `llm/P3-<time>-E1_canary_matrix/` | `result.json` (provenance, configuration, summary, classification, limitations) and `observations.jsonl` (one row per trial). Same layout for E2 to E5. |
| `llm/revalidation_rc2_unmodified/` | The Phase 1/2 `model_experiments.py` (M1 to M6), run unmodified on the unmodified Phase 2 candidate (tree `7ac1fb71...`). |
| `llm/revalidation_candidate_tree/` | The same script on the Phase 3 tree. |
| `dev_smoke/` | Superseded development runs; see its README. Not claims. |

## Experiments

| Id | Question | Needs |
|---|---|---|
| E1 | Does a canary planted in one session come back in another, through the adapter alone (fresh/reused server, prompt cache off/on, adjacent/late/concurrent, negative control, two positive controls)? | model |
| E2 | The same through the full pipeline (broker, rootless sandboxes, real model), sequential and concurrent runs, wire recording | model, Podman |
| E3 | Is there a shared KV / prompt-cache mechanism, and can a second session observe it? What do `/slots` and `/props` expose? | model |
| E4 | Prompt injection and output isolation; model-generated gate-bypass text replayed against the mailbox and the API | model, Podman |
| E5 | Kill during a request, repeated and intermittent failures, unreachable server | model, Podman |

## Reproduce

    cd aegislab && . .venv/bin/activate
    python evaluation/llm_isolation.py --server-dir <dir with llama-server> --model <file.gguf> \
        --out-dir evidence/phase3_2026-10-23/llm --state-dir <empty scratch dir> --only E2,E3,E4,E5,E1 \
        --sessions 16 --pipeline-runs 8 --injection-runs 3 --kv-trials 30 --seed 3
    python evaluation/check_claims.py          # recomputes every figure from observations.jsonl and checks the report

The checker fails if a stored figure differs from the recomputed one, if a result or observation file no longer matches its recorded hash, or if a source file listed in `source_sha256` has changed since the run (re-run the experiment after changing `aegis/model_client.py`, `aegis/runs.py`, `aegis/evidence.py`, `aegis/api.py`, the sandbox files, the samples or the two `llm_*.py` files). A run without the model is reported as `not run`, never as a pass.
