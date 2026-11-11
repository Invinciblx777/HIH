# Finale P4 evidence (11 Nov 2026): hardening, re-measured

Everything here was measured on 11 Nov 2026 on the test host (Fedora 45, kernel 7.2.15, Python 3.15, rootless Podman 6.1.3, crun 1.30.1, SELinux enforcing; CPU only). `evaluation/check_claims.py` recomputes every figure below from the raw files in this directory (Part F) and checks that this README quotes each one verbatim.

## Code

- Branch `finale/p4-hardening`, from 4b82814. One commit per task; see `docs/finale/P4_REPORT.md` (outside the repository) for the list.
- **First pass, commit e048ad9** (all P4 tasks, deadline release available but not the default): every step in the table below except the last two.
- **Final pass, commit 032eb84** (deadline release becomes the real-model default, `runs.default_timing`): the F4 proof and E1-E5 were re-run, because both record `aegis/runs.py` and `aegis/api.py`, which that commit changed. The first-pass copies (`llm/`, `userns_proof/`) are kept as recorded and superseded by `llm_final/` and `userns_proof_final/`. Part F reads only the final ones, and allows no acknowledgement for them.
- The other measurements were not re-run after 032eb84. They use the stub model and pass an explicit timing choice, or get the stub default (250 ms buckets, unchanged), so the policy of every run they create is byte-identical (`REMEASURED.json`, `after_the_measurement`). The two timing experiments pass explicit settings.

Pinned files changed since 4b82814 are acknowledged in `SOURCE_DRIFT.json` (the third file in `check_claims.SOURCE_DRIFT_FILES`). E1 and E3 of the older runs carry `"affects": false` with a reason. E2, E4, E5 and the hardening check carry `"affects": true` and name the re-measurement here that supersedes them (`llm_final/`, `model_server_hardening/`); the checker accepts that only while the re-measurement shows no source drift at all.

## Measurement hygiene

Every step ran alone, in sequence, from one driver; nothing else was started on the host meanwhile. No container was running when any step started. Load averages (1, 5, 15 min) are from `/proc/loadavg` immediately before and after each step (`round2/logs/finale_p4/measure_steps.jsonl`, outside the repository):

| Step | Exit | Wall clock (s) | Load before | Load after |
|---|---|---|---|---|
| userns_proof | 0 | 12 | 0.26 0.52 0.56 | 0.59 0.58 0.58 |
| validation | 0 | 152 | 0.59 0.58 0.58 | 1.37 0.95 0.73 |
| phase2_matrix | 0 | 4 | 1.37 0.95 0.73 | 1.34 0.96 0.73 |
| e1_e9 | 0 | 205 | 1.34 0.96 0.73 | 0.70 0.91 0.76 |
| llm_e1_e5 | 0 | 2024 | 0.70 0.91 0.76 | 5.77 5.97 5.35 |
| m1_m6 | 0 | 270 | 5.77 5.97 5.35 | 4.10 5.42 5.32 |
| hardening | 0 | 27,656 (includes a system suspend, see below) | 3.85 5.34 5.30 | 7.33 6.39 5.74 |
| timing_stub_exec1 | 0 | 732 | 7.33 6.39 5.74 | 6.75 3.06 3.73 |
| timing_stub_exec2 | 0 | 651 | 6.75 3.06 3.73 | 2.83 1.72 2.49 |
| timing_stub_exec3 | 0 | 649 | 2.83 1.72 2.49 | 6.56 2.72 2.33 |
| timing_stub_aggregate | 0 | 1 | 6.56 2.72 2.33 | 6.56 2.72 2.33 |
| timing_deadline_exec1 | 0 | 1389 | 6.56 2.72 2.33 | 1.11 1.43 1.96 |
| timing_deadline_exec2 | 0 | 1455 | 1.11 1.43 1.96 | 1.22 1.58 2.25 |
| timing_deadline_exec3 | 0 | 1388 | 1.22 1.58 2.25 | 1.16 1.52 2.03 |
| timing_deadline_aggregate | 0 | 0 | 1.16 1.52 2.03 | 1.16 1.52 2.03 |
| userns_proof_final | 0 | 8 | 0.66 0.74 1.43 | 0.77 0.76 1.44 |
| llm_e1_e5_final | 0 | 2003 | 0.77 0.76 1.44 | 6.06 6.05 5.51 |

Notes, as measured:
- **System suspend.** The laptop suspended at 02:05:20 during the hardening step and resumed at about 09:42 (systemd-logind, requested by the desktop's power manager). The step then completed normally, and its result is a count of cached prompt tokens per trial and an AUC over those counts, which a pause does not change. Its wall clock includes the suspend. From then on a `systemd-inhibit` sleep lock was held for the rest of the measurements.
- **Load at the start of `timing_stub_exec1`** was 7.33 (1 min). It is the decaying average of the hardening step that had just ended (llama.cpp with 6 threads); no other process was busy (checked with `top`). The stub timing executions raise the 1-min load themselves (about 6.5) by starting three containers per run.
- The real-model steps (`llm_*`, `m1_m6`, `hardening`, `timing_deadline_*`) load the host by design: llama.cpp runs with 6 threads.

## Real model E1-E5, final pass (`llm_final/`, Qwen2.5-0.5B Q4_K_M, llama.cpp b11819 on CPU)

Command: `.venv/bin/python evaluation/llm_isolation.py --server-dir <llama.cpp-b11819> --model <qwen2.5-0.5b-instruct-q4_k_m.gguf> --out-dir evidence/finale_p4_2026-11-11/llm_final --state-dir <scratch> --only E2,E3,E4,E5,E1 --sessions 16 --pipeline-runs 8 --injection-runs 3 --kv-trials 30 --seed 3` (33 minutes).

- E1: 0 of 1040 isolation trials leaked (0 of 104 sessions); one-sided 95% upper bound 0.29% of trials, 2.84% of sessions; 0 of 320 negative-control trials leaked; positive controls: shared history 16 of 16 sessions, sharing gateway 13 of 16 sessions. E1 classification: pass.
- E2: 0 of 26 isolation runs (312 attacks) had a foreign canary in raw model output; 0 reached red; context-sharing control: foreign canary in raw model output in 2 of 4 runs, 17 attacks withheld from red, 0 reached red; negative control: 0 of 4 runs. E2 classification: pass.
- E3: cache_prompt=true: cached-token AUC 1.00/1.00 with 30+30 trials per cell in 2 cells; cache_prompt=false (AegisLab default): cached tokens observed in 0 of 120 trials; fresh process per trial: cached tokens observed in 0 of 14 trials; client-visible latency, wrong guess slower than correct guess (AUC): cache_prompt=true 1.00/1.00, cache_prompt=false 0.41/0.56. E3 classification: pass.
- E4: 72 injection attacks (69 reached the model): 0 protected values in red-visible output; 282 of 282 replayed model-generated gate messages denied, 0 changed run state. E4 classification: pass.
- E5: failure handling: 9 of 9 checks hold. E5 classification: pass.

Differences from earlier runs, both reported:
- The context-sharing control (built to leak) put a foreign canary in the raw model output in 2 of 4 runs. It was 3 of 4 on 10 Nov, 2 of 4 on 23 Oct, and 16 foreign canaries in the first P4 pass. No such canary reached red in any run.
- The cache-off latency AUC was 0.41/0.56. It was 0.41/0.47 on 10 Nov and 0.52/0.42 on 23 Oct. It is a latency figure on a shared CPU and is not an isolation result; the cached-token count, which is, was 0 of 120.

## M1-M6 (`model_experiments_M1_M6.json`)

finale P4 tree (11 Nov 2026): canary leaks 0/80 and 0/80, marker hits 0 in 270 responses, API key in run files: 0, failure cases ending FAILED with a verified terminal checkpoint: 3 of 3.

## Hardened model server with the F4 user namespace (`model_server_hardening/`)

hardened launcher, F4 user namespace: cached prompt tokens in 0 of 120 broker-style trials and 0 of 120 field-absent trials (host process and sandbox); a client sending cache_prompt=true still gets them (AUC 1.00/1.00).

Command: `AEGIS_VAR=<scratch> .venv/bin/python evaluation/model_server_hardening.py --out-dir evidence/finale_p4_2026-11-11/model_server_hardening --trials 30`.

## F4: no container runs as the key owner (`userns_proof_final/`)

F4: 4 containers sampled live (red, blue, model worker, sandboxed model server), all as container UID 900 on distinct host UIDs 525188/526212/527236/528260; none as the broker's UID 1000; the evidence key bind-mounted into a container is unreadable (errno 13).

Command: `AEGIS_VAR=<scratch> .venv/bin/python evaluation/p4_userns_proof.py --out-dir evidence/finale_p4_2026-11-11/userns_proof_final`. The proof starts the sandboxed model server first, then a real lab run, and samples every container while it runs (`podman top` user and huser, `/proc/<pid>/status`, `/proc/<pid>/uid_map`). It ends with two negative controls: the key directory as a mount source (refused by the guard), and a raw `podman run` with the same flags and the scratch key directory bind-mounted read-only (reading the key fails with errno 13). The first pass on e048ad9 (`userns_proof/`) gave the same 13 of 13 checks and the same host UIDs.

## Container-only re-measurement on the F4 runtime (`validation/`, `role_matrix_extended.json`, `e1_e9_rerun/`)

Commands and hashes: `REMEASURED.json`. The same checks as the finale P2 re-baseline (Part D), on e048ad9: 181/181 unauthorized API cases denied, 0 secret markers in 216 public GET bodies, 92/92 traversal cases rejected, 19/19 tamper categories detected 30/30, the CLI accepts 10/10 genuine and rejects 40/40 tampered bundles, the extended matrix denies 419/419 and allows 141/141 of 560 attempts, and in E2 the red sandbox's 150/150 forbidden requests are denied, 90/90 connects fail and 240/240 foreign paths are absent.

## Timing with the stub model, 3 executions (`timing_stub/`)

stub model, 3 executions, 11 Nov 2026 (P4 code, writes before the padded reply): held-out accuracy 0.640-0.800 at 0 ms, 0.530-0.555 at 100 ms, 0.435-0.540 at 250 ms, 0.410-0.515 at 500 ms; pooled at 250 ms 0.490 (95% CI 0.450-0.530, n=600); smallest padded p 0.123; 250 ms cost +197 to +197 ms per answered request.

Command per execution: `AEGIS_VAR=<scratch> .venv/bin/python evaluation/timing_closeout.py --seed 2026111k --out-dir evidence/finale_p4_2026-11-11/timing_stub/execk_seed2026111k` (k = 1, 2, 3), then `evaluation/timing_aggregate.py`. This is a regression check on the P4 code, in which every decision-dependent write happens before the padded reply. The figures agree with the 22 Oct closeout: no padded setting is significant.

## Timing with the real model, 3 executions, deadline release (`timing_deadline/`)

real-model timing, 3 executions, 11 Nov 2026, balanced classes, every payload in both classes: unpadded: accuracy 1.000/1.000/1.000 (baseline-adjusted +0.500/+0.500/+0.500, p 0.0010/0.0010/0.0010); 250 ms buckets: accuracy 0.945/0.960/0.950 (baseline-adjusted +0.445/+0.460/+0.450, p 0.0010/0.0010/0.0010); deadline: accuracy 0.495/0.545/0.575 (baseline-adjusted -0.020/+0.005/+0.060, p 0.5604/0.1968/0.0440); deadline + shadow call: accuracy 0.455/0.505/0.560 (baseline-adjusted -0.065/-0.030/+0.045, p 0.8302/0.4715/0.1179).

deadline cost per answered request (median, vs unpadded): +519/+621/+529 ms; cut-off rate of requests that reached the model: 0.030/0.080/0.030.

The deadline D was fixed per execution from a calibration phase before any classification run: 1300, 1400 and 1300 ms. Calibration ran 12 unpadded runs (120 requests). D is the p99 of the broker's decision time for requests that reached the model, plus 100 ms, rounded up to 100 ms. The verdict rule was declared before the runs: a padded setting is "leak detected" if its permutation p < 0.05/9 in any execution. Result: 250 ms buckets, leak detected; deadline and deadline with the shadow call, no leak detected (inconclusive as to absence). The third execution's deadline p (0.044) is below 0.05 but above the declared threshold, and is reported as it is.

Also recorded per run, as measured:
- every deadline reply was released at most 1.35 ms after t0 + D, and none overran;
- a 10-attack run took 9.4 to 10.4 s longer than unpadded;
- the model server's CPU time per run (median) was 20.5 to 21.9 s with deadline release and 24.9 to 27.2 s with the shadow call.

Command per execution: `AEGIS_VAR=<scratch> .venv/bin/python evaluation/timing_deadline.py --seed 2026112k --out-dir evidence/finale_p4_2026-11-11/timing_deadline/execk_seed2026112k --runs 20 --calib-runs 12` (k = 1, 2, 3; about 23 minutes each), then `--aggregate`.

These results made deadline release the default for a real-model backend (commit 032eb84, with the owner's approval), at D = 1400 ms, the largest of the three calibrated values. The stub keeps 250 ms buckets.

## Not re-measured here

- The 23 Oct Phase 3 runs and the 10 Nov finale P3 runs (Qwen2.5-0.5B and the reduced Qwen2.5-1.5B set) stay as recorded and are still checked (Parts C and E), through `SOURCE_DRIFT.json`.
- The P3 single-execution real-model timing (`evidence/finale_p3_2026-11-10/timing_real_model/`) is superseded by the three executions above, which remove its two confounders (unbalanced classes; refusal tied to the payload).
