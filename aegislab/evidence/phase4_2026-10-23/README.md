# Phase 4 evidence (23 Oct 2026)

| File | What it is |
|---|---|
| `judge_demo_transcript.txt` | Output of a real, successful execution of `bash scripts/judge_demo.sh` (presentation mode, stub model, fresh state, 17 / 17 checks). Use it as the fallback if a live run fails; present it as a recording. |
| `judge_demo_transcript.json` | The same lines with their time offsets in seconds (`--record`). The deck and the video show excerpts of this text, unedited. |
| `validation_results.json` | The executed validation counts of this release (tests, quickstart, demos, checkers) that the deck quotes; written by the Phase 4 validation. |

Step 6 of the demo prints PRECOMPUTED real-model results (runs under `../phase3_2026-10-23/llm/`); no model runs in the demo. The `[HISTORICAL]` block in step 3 quotes `../phase2_2026-10-23/before_fix/11_poc_mailbox.txt`, a result recorded earlier on the Phase 1 broker.
