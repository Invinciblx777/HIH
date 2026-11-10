# Grand Finale P3: the real model, live and re-measured, 10 Nov 2026

P3 makes the LLM-native objective live with a real model and re-measures the saved real-model evidence on the current code.

- **Code.** Commit `09b53d1` on `finale/p3-real-model`, stacked on `finale/p2-rebaseline` (`947af3e`). It changed:
  - `aegis/model_client.py`: optional UNIX-socket transport and a declared model identity;
  - `evaluation/llm_common.py`: the harness passes its key with `--api-key-file`;
  - `evaluation/llm_isolation.py`: `--model-class`.

  New scripts: `scripts/start_model_server.sh`, `scripts/start_real_model_console.sh`, `scripts/real_model_demo.sh`, `scripts/real_model_console_check.py`, `evaluation/model_server_hardening.py`, `evaluation/timing_real_model.py`.
- **Every earlier evidence folder is untouched.** That includes `../phase3_2026-10-23/llm/INDEX.json` and `../validation_2026-10-22/model_experiments.json`.
  - The 23 Oct runs are still checked (`evaluation/check_claims.py` Part C).
  - Their source drift is acknowledged in `SOURCE_DRIFT.json` here. That file adds to the P2 file `../finale_rebaseline_2026-11-10/SOURCE_DRIFT.json` and does not replace it.
- **The newest run of each experiment is the current one.** `check_claims.latest_real_model()` picks `llm/` here when it exists. The judge demo, the security demo and the console's Experiments page all say which set they show, with where and when it was recorded.
- **Model and server (outside the repository, never committed):**
  - `qwen2.5-0.5b-instruct-q4_k_m.gguf`, sha256 `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`;
  - `llama-server` from llama.cpp b11819 (CPU), sha256 `17d2573dede0314fe681f3c2c821a9a44818949e1073200292353efb21c426bb`.

  Both are the files the 23 Oct evidence was recorded with. They were copied (not moved) into `_models/` and re-hashed.
- **Host.** One Fedora laptop: 16 CPUs, 14 GB RAM, no GPU, SELinux enforcing, rootless Podman 6.1.3.

## Re-measured on the current code

All commands run from `aegislab/` with a scratch `AEGIS_VAR` and `--state-dir` outside the repository. `M` is the models folder.

| Folder / file | Command | Wall time |
|---|---|---|
| `llm/` (E1–E5, own `INDEX.json`) | `.venv/bin/python evaluation/llm_isolation.py --server-dir $M/llama.cpp-b11819/llama-b11819 --model $M/qwen2.5-0.5b-instruct-q4_k_m.gguf --out-dir evidence/finale_p3_2026-11-10/llm --state-dir <scratch> --only E2,E3,E4,E5,E1 --sessions 16 --pipeline-runs 8 --injection-runs 3 --kv-trials 30 --seed 3` (the 23 Oct settings) | 1917 s |
| `model_experiments_M1_M6.json` | `.venv/bin/python evaluation/model_experiments.py --server-dir … --model … --out evidence/finale_p3_2026-11-10/model_experiments_M1_M6.json --sessions 20 --seed 1` (script unchanged) | 262 s |

Started 2026-11-10T12:06:41Z on commit `09b53d1`.

- E3 overlapped a short trial of the hardening check on the same host. CPU contention may have affected E3's latency figures; it does not affect its cached-token counts.
- E1 and M1–M6 ran with nothing else measuring.

### Compared with the 23 Oct runs

Each figure below is recomputed from the raw files by `evaluation/check_claims.py`. Part E prints this comparison with `<-- differs` against each changed figure.

| Figure | 23 Oct 2026 | 10 Nov 2026 |
|---|---|---|
| E1 isolation | 0 of 1040 trials (0 of 104 sessions) | same |
| E1 bound | 0.29% of trials, 2.84% of sessions | same |
| E1 negative controls | 0 of 320 trials | same |
| E1 positive controls | shared history 16 of 16 sessions, sharing gateway 13 of 16 | same |
| E2 pipeline isolation | 0 of 26 runs (312 attacks); 0 reached red | same |
| E2 negative control | 0 of 4 runs | same |
| **E2 context-sharing control** | foreign canary in raw model output in **2 of 4** runs, **15** attacks withheld, 0 reached red | **3 of 4** runs, **14** attacks withheld, 0 reached red |
| E3 cache oracle | cache on: AUC 1.00/1.00; cache off 0 of 120 trials; fresh process 0 of 14 | same |
| **E3 client-visible latency AUC, cache off** | **0.52/0.42** | **0.41/0.47** (cache on 1.00/1.00 both dates) |
| E4 injection | 72 attacks (69 reached the model); 0 protected values to red; 282 of 282 replays denied | same |
| E5 failure handling | 9 of 9 checks | same |
| M1, M2 (22 Oct file) | 0/80 and 0/80 leaks, 0/20 and 0/20 contamination; controls 17/20, 20/20, 20/20, 0/20; context control 17/20 | same |
| M3 cached tokens on a reused server with `cache_prompt:true` | 162 (fresh process: 0) | same |
| **M3 median probe latency** | **242.3 ms** reused vs **700.1 ms** fresh | **227.5 ms** vs **647.9 ms** |
| M4/M5, M6 | pipeline and failure behaviour | same |

The three differences are in controls and latency figures, not in an isolation result.

- **The context-sharing control.** It deliberately shares context, so any number of leaking runs above 0 shows the detector works. llama.cpp on CPU is not bit-for-bit reproducible across runs, even at temperature 0, so the model's wording, and with it the leak count, can change.
- **The latency figures** depend on host load.
- Nothing was tuned or re-run to change a figure.

## The hardened, sandboxed model server (`model_server_hardening/`)

`scripts/start_model_server.sh` is the only launcher the live paths use. Its header lists every flag and what it closes. `evaluation/model_server_hardening.py` starts it in both modes and measures the result:

- **`--host-process`:** `127.0.0.1`, random port.
- **`--sandbox`:** rootless Podman with `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --userns keep-id`, pids, memory and CPU limits, read-only mounts, and a UNIX socket in a 0700 directory.

What it measures:

- **Cache oracle.** Cached prompt tokens with a planted-prefix oracle, for three request variants: AegisLab's own (`cache_prompt:false`), the field absent, and a client sending `cache_prompt:true`. A control runs the harness's default server.
- **Endpoints.** Every endpoint, with and without the key.
- **Key exposure.** The key on every process command line.
- **Sandbox.** Network, filesystem, capability and limit facts, read from inside the container.

```bash
AEGIS_VAR=<scratch> .venv/bin/python evaluation/model_server_hardening.py --out-dir evidence/finale_p3_2026-11-10/model_server_hardening --trials 30
```

Run `P3H-20261110T132637Z`, 13:22–13:26 UTC, 30+30 trials per cell, 14 of 14 checks hold. An earlier start overlapped the end of M1–M6 (which ended 12:43 UTC); it was stopped, and wrote nothing here.

| Cell | Trials with cached prompt tokens |
|---|---|
| host-process / AegisLab request (`cache_prompt:false`) | 0 of 60 |
| host-process / field absent | 0 of 60 |
| host-process / client sends `cache_prompt:true` | 60 of 60 (AUC 1.0) |
| sandbox / AegisLab request | 0 of 60 |
| sandbox / field absent | 0 of 60 |
| sandbox / client sends `cache_prompt:true` | 60 of 60 (AUC 1.0) |
| control: harness server without the launcher flags, field absent | 60 of 60 (AUC 1.0) |

Endpoints:
- `/slots`, `/metrics`, `POST /props` and slot save/restore answer 501.
- Without the key, every endpoint except `/health` answers 401.
- No prompt text or planted marker appears in any endpoint.

Key:
- The key is on no process command line.
- It is not in `launch.json` or `model.env`.

Sandbox, read from inside the container:
- only `lo`; `connect` to 1.1.1.1 fails with errno 101;
- read-only root filesystem; `CapEff` 0, `NoNewPrivs` 1;
- `NetworkMode` none, 64 pids, 3 GiB memory, 6 CPUs;
- binary, library, model and key mounted read-only.

What the flags **cannot** close, recorded in the result as `what_is_not_closed`:

- **Client-requested caching.** A client that sends `cache_prompt:true` still reuses the slot's KV prefix: `--no-cache-prompt` sets only the default in b11819. This is closed only because the broker is the only client and refuses to send it (P2 guard). In `--sandbox` mode, only processes of the same Unix user can reach the socket.
- **`GET /props`.** It cannot be turned off. It needs the key and shows defaults and the model path, no prompt text.
- **Shared hardware state.** The live KV cells of the single slot between requests, CPU caches, memory bandwidth and timing.
- **Untested.** GPU or accelerator memory (CPU build only), other inference servers and other builds.

## The real model, live

| What | Command | Evidence |
|---|---|---|
| Four live checks, one PASS/FAIL line each | `bash scripts/real_model_demo.sh` | run three times in a row for P3 (logs in the P3 report) |
| The console with the real model, driven in Chromium: lifecycle, four scenarios, verify, tamper | `.venv-browser/bin/python scripts/real_model_console_check.py --shots <outside the repo> --keep-bundle evidence/finale_p3_2026-11-10/live_console_bundle/LAB-001` | `live_console_bundle/LAB-001`: the reviewer-exported bundle of that run |

Verify the live run's bundle (exit 0). Its signed `model.session_opened` entry names the model file, its sha256 and `rootless-podman-network-none`:

```bash
python -m aegis.verify_cli --bundle evidence/finale_p3_2026-11-10/live_console_bundle/LAB-001 --run-id LAB-001 --expect-state RELEASED
```

## Real-model timing, ONE execution (`timing_real_model/`)

This closes the gap stated in `../../THREAT_MODEL.md` row 5: "a real model's variable latency can cross bucket boundaries (not measured)". It is **one** execution; the stub timing evidence (`../closeout_2026-10-22/timing/`, untouched) has three.

- **Procedure.** The same classifier and analysis as the stub executions. `timing_closeout.classification` and `timing_eval.analyse` are reused unchanged.
- **Calibration.** Eight unpadded calibration runs fix a third padding setting, `ceil(p99 of answered latency / 100 ms) * 100 ms`. It is written to `result.json` before any classification run.
- **Classification.** 20 runs per setting at 0 ms, 250 ms and that bucket, interleaved in a seeded order.
- **Raw files.** `raw_calibration.jsonl`, `raw_runs.json` and `raw_classification.jsonl`, hashed in `result.json`.

```bash
AEGIS_VAR=<scratch> .venv/bin/python evaluation/timing_real_model.py --seed 20261110 --runs 20 --calib-runs 8 --out-dir evidence/finale_p3_2026-11-10/timing_real_model
```

Ran 2026-11-10 12:43–13:22 UTC (2339 s) with nothing else measuring. Execution `TR-20261110T124316Z-3df75b`.

| Setting | Held-out accuracy (majority baseline 0.700) | Permutation p | Verdict (α 0.05/2) | Answered latency median / p99 | Refused median |
|---|---|---|---|---|---|
| 0 ms (unpadded) | 1.000 | 0.001 | — | 1074 / 1816 ms | 126 ms |
| 250 ms (shipped default) | **1.000** | 0.001 | **leak detected** | 1313 / 4160 ms | 375 ms |
| 1600 ms (calibration p99 1584 ms, rounded up) | 0.640 | 0.055 | no leak detected (inconclusive as to absence) | 1725 / 3326 ms | 1725 ms |

What the table shows:

- **250 ms does not hide the decision with a real model.** The model's own latency (answered 264–1956 ms unpadded) spans many 250 ms buckets, while refusals never reach the model.
- **The p99 bucket.** It cost +651 ms median per answered request. Answered requests above the p99 still landed in a later bucket (p99 3326 ms), which is the signal left.
- **One execution.** With n=200, an accuracy up to about 0.07 above baseline cannot be told from chance.
- **Erratum (recording metadata only).** `result.json` `config.classes_per_run` and one confounder line say "5 refused / 5 answered". The raw file shows **3 refused and 7 answered in every run** (A02, A03 and A10 are refused), 60 and 140 in total. That is why the majority baseline is 0.700. The analysis reads the labels from the raw file, so no figure is affected. The script now records the observed split (`classes_per_run_observed`); the file is left as recorded.

## Second model, reduced (`llm_qwen2.5-1.5b/`)

Qwen2.5-1.5B-Instruct Q4_K_M from the official Qwen repository. It is outside the repository and never committed.

- **Source:** `https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/91cad51170dc346986eccefdc2dd33a9da36ead9/qwen2.5-1.5b-instruct-q4_k_m.gguf` (apache-2.0).
- **sha256:** `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`. This equals the Hugging Face LFS pointer. Size 1117320736 bytes.
- **What ran:** a reduced E1 and E3 only, 4 sessions per E1 cell instead of 16, E3 with the same 30+30 trials. It is a breadth check, not a replacement.

  ```bash
  .venv/bin/python evaluation/llm_isolation.py --server-dir $M/llama.cpp-b11819/llama-b11819 --model $M/qwen2.5-1.5b-instruct-gguf/qwen2.5-1.5b-instruct-q4_k_m.gguf --out-dir evidence/finale_p3_2026-11-10/llm_qwen2.5-1.5b --state-dir <scratch> --only E3,E1 --sessions 4 --kv-trials 30 --seed 3 --model-class "Qwen2.5-1.5B-Instruct Q4_K_M (1.5B parameters)"
  ```

  13:26–18:01 UTC (16455 s). It overlapped the Playwright console run (13:33–13:35), which does not affect leak or cached-token counts.
- **Result:** 0 of 280 isolation trials leaked (0 of 28 sessions). Both positive controls detected the leak (4 of 4 and 3 of 4 sessions). The E3 oracle shows the same pattern as the 0.5B model. With 28 sessions, the upper bound is wide: 10.15% of sessions.
- **Index:** it has its own `INDEX.json`, so it never replaces the 0.5B set as "latest".

## Figures, as `evaluation/check_claims.py` recomputes them

Part E fails if any of these strings is missing here.

### Re-measured E1–E5 (Qwen2.5-0.5B, `llm/`)

- one-sided 95% upper bound 0.29% of trials, 2.84% of sessions
- E1 classification: pass
- 0 of 320 negative-control trials leaked
- positive controls: shared history 16 of 16 sessions, sharing gateway 13 of 16 sessions
- 0 of 1040 isolation trials leaked (0 of 104 sessions)
- E2 classification: pass
- 0 of 26 isolation runs (312 attacks) had a foreign canary in raw model output; 0 reached red
- negative control: 0 of 4 runs
- context-sharing control: foreign canary in raw model output in 3 of 4 runs, 14 attacks withheld from red, 0 reached red
- E3 classification: pass
- fresh process per trial: cached tokens observed in 0 of 14 trials
- cache_prompt=false (AegisLab default): cached tokens observed in 0 of 120 trials
- cache_prompt=true: cached-token AUC 1.00/1.00 with 30+30 trials per cell in 2 cells
- client-visible latency, wrong guess slower than correct guess (AUC): cache_prompt=true 1.00/1.00, cache_prompt=false 0.41/0.47
- 72 injection attacks (69 reached the model): 0 protected values in red-visible output; 282 of 282 replayed model-generated gate messages denied, 0 changed run state
- E4 classification: pass
- failure handling: 9 of 9 checks hold
- E5 classification: pass

### M1–M6 (`model_experiments_M1_M6.json`)

- finale P3 tree (10 Nov 2026): canary leaks 0/80 and 0/80, marker hits 0 in 270 responses, API key in run files: 0, failure cases ending FAILED with a verified terminal checkpoint: 3 of 3

### Hardened model server

- hardened launcher: cached prompt tokens in 0 of 120 broker-style trials and 0 of 120 field-absent trials (host process and sandbox); a client sending cache_prompt=true still gets them (AUC 1.00/1.00)

### Real-model timing

- real-model timing, ONE execution, 10 Nov 2026 (calibration: answered p50 858 ms, p99 1584 ms): held-out accuracy 1.000 at 0 ms (p=0.0010), 1.000 at 250 ms (p=0.0010), 0.640 at 1600 ms (p=0.0549) (majority baseline 0.700/0.700/0.700)

### Second model (Qwen2.5-1.5B, reduced, `llm_qwen2.5-1.5b/`)

- Qwen2.5-1.5B: one-sided 95% upper bound 1.06% of trials, 10.15% of sessions
- Qwen2.5-1.5B: E1 classification: pass
- Qwen2.5-1.5B: 0 of 80 negative-control trials leaked
- Qwen2.5-1.5B: positive controls: shared history 4 of 4 sessions, sharing gateway 3 of 4 sessions
- Qwen2.5-1.5B: 0 of 280 isolation trials leaked (0 of 28 sessions)
- Qwen2.5-1.5B: E3 classification: pass
- Qwen2.5-1.5B: fresh process per trial: cached tokens observed in 0 of 14 trials
- Qwen2.5-1.5B: cache_prompt=false (AegisLab default): cached tokens observed in 0 of 120 trials
- Qwen2.5-1.5B: cache_prompt=true: cached-token AUC 1.00/1.00 with 30+30 trials per cell in 2 cells
- Qwen2.5-1.5B: client-visible latency, wrong guess slower than correct guess (AUC): cache_prompt=true 1.00/1.00, cache_prompt=false 0.47/0.54

## Files

| Path | What it is |
|---|---|
| `SOURCE_DRIFT.json` | Acknowledges, for the **23 Oct** runs only, the three source files P3 changed (exact old → new hash, per experiment why it does not affect what was measured). The re-measured runs here may not use any acknowledgement |
| `llm/` | E1–E5 re-measured (0.5B), own `INDEX.json` |
| `llm_qwen2.5-1.5b/` | reduced E1 + E3 with the 1.5B model, own `INDEX.json` |
| `model_experiments_M1_M6.json` | M1–M6 re-run (script unchanged) |
| `model_server_hardening/P3H-*/` | the launcher check (`result.json`, `observations.jsonl`) |
| `timing_real_model/` | one real-model timing execution with raw files |
| `live_console_bundle/LAB-001/` | the reviewer-exported bundle of the Playwright real-model console run (verifies strictly; its manifest records the transient socket path, never the key) |
