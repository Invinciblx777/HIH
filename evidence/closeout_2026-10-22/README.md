# Phase 1 closeout evidence (22–23 Oct 2026)

Separate from, and never overwriting, the submitted 15 Oct results (`../results.json`, `../RESULTS.md`, `../DEMO-001/`) and the earlier 22 Oct validation (`../validation_2026-10-22/`). Nothing there was edited. This folder holds (1) three fresh timing executions with raw data, (2) the record of the earlier timing executions, and (3) a completed, released `DEMO-001` bundle that passes the strict verifier.

## Layout

| Path | What it is |
|---|---|
| `timing/exec1_seed20261022/`, `exec2_seed20261023/`, `exec3_seed20261024/` | One execution each: `result.json` (run id, timestamps, config, rules, per-file source sha256, host, metrics, sha256 of the raw files), `raw_classification.jsonl` (800 requests: run id, padding, attack id, latency, refused), `raw_runs.json` (every run, with failures), `raw_rtt.jsonl` (3600 timed round trips incl. warm-ups, flagged), `rtt_blocks.json` (condition, validity, host CPU busy %, load per block) |
| `timing/exec*.stdout.log`, `timing/EXIT_CODES.txt` | Console output and exit code (0) of each execution |
| `timing/aggregate.json` | Side-by-side executions, pooled counts, leave-one-execution-out transfer, verdicts, round-trip ranges (written by `evaluation/timing_aggregate.py`; no run is averaged away) |
| `timing/historical/` | Record of the earlier timing executions: console extract of the one with no raw file, the diff of its script against the shipped script, the surviving per-request files of the other two and the reproduction of their stored results |
| `DEMO-001_released/` | Completed, released run from the 22 Oct code, strict-verifiable (see below); `DEMO-001_released_verification_log.txt` is the verifier output for the genuine bundle, three tampered copies and the legacy bundle |

## Provenance of the timing executions

| | exec 1 | exec 2 | exec 3 |
|---|---|---|---|
| Run id | `TX-20261022T175008Z-4fbc95` | `TX-20261022T175843Z-0cb504` | `TX-20261022T180713Z-df7f7e` |
| Seed (fold assignment, shuffles; fixed in advance) | 20261022 | 20261023 | 20261024 |
| Wall clock | 495 s | 489 s | 529 s |
| Exit code, status | 0, COMPLETE | 0, COMPLETE | 0, COMPLETE |
| Unusable runs / RTT blocks | 0 / 0 | 0 / 0 | 0 / 0 |

* **Code tested.** Tree hash `sha256:d5850aa4dc82570f2ee9b8e6a6fe678d8f31399a43686ac5fabe97f2cd8af100` (33 files), identical in the three executions. All 32 files that exist in the shipped 22 Oct release (tree hash `6133ff0a…`) are **byte-identical** to the shipped files (compare `source_sha256` in each `result.json` with `MANIFEST.sha256`); the 33rd is `evaluation/timing_closeout.py` (sha256 `a88bfa637df3610f2de29726b0893ae3d6a9de84af1846e92047afcfc5e72065`). `evaluation/timing_eval.py` (sha256 `6f793132…`) is unchanged and is the code whose functions the harness runs. The candidate release adds `evaluation/timing_aggregate.py` and changes `evaluation/check_claims.py` and `scripts/security_demo.py` after the executions; none of them is part of the measurement. The candidate's own tree hash is `sha256:c42dfecdb170206f107c4df1dfa17d02d0c8866f3f825abad82b49c9e05ea44c` (34 files).
* **Host.** Fedora, kernel 7.2.11-200.fc44, AMD Ryzen 7 7735HS (16 threads, governor `performance`), rootless Podman 5.8.9, crun 1.28, cgroups v2, SELinux enforcing, Python 3.14.8, cpuset controller not delegated. A normal desktop session (browser, editors, file indexer) was running; the three highest-CPU processes before each start are in `result.json`. `loadavg_before` of executions 2 and 3 still contains the tail of the previous execution (20 s pause between executions).
* **Image.** `localhost/aegislab-sandbox:0.1` built from the shipped `Containerfile` on `python:3.12-slim`; the image id is in each `result.json`.

## Method and definitions

Command: `AEGIS_VAR=<fresh scratch> python evaluation/timing_closeout.py --seed <n> --out-dir timing/exec<k>_seed<n>`; then `python evaluation/timing_aggregate.py --out timing/aggregate.json timing/exec*_seed*`.

* **Classification.** Padding settings 0, 100, 250, 500 ms, fixed in advance (250 ms is the shipped default, chosen on 15 Oct data; none of the settings was changed in response to these results). 20 runs per setting per execution, 10 attacks per run (5 refused, 5 answered), so 200 requests (100 + 100) per setting; majority baseline 0.50. Runs of the four settings are interleaved in a seeded random order. Latency is the `time.perf_counter()` delta measured inside the red sandbox around each `attack` call. Classifier: single latency threshold (direction included) fitted on the training runs only, scored on held-out runs, grouped 5-fold by run. Permutation p: 1000 shuffles of the labels across requests, full procedure repeated. Leave-one-execution-out: threshold fitted on the other two executions, scored on this one.
* **Verdict rule, fixed before any result was inspected** (Bonferroni family: 3 executions × 3 padded settings, α = 0.05/9 = 0.0056): *leak detected* if any execution has p < α; *leak likely* if all three have p < 0.05; *unstable* if some do and some do not; otherwise *no leak detected (inconclusive as to absence)*. The fourth category and the aggregation code were written before the executions finished; `result.json` stores the first three clauses (the *leak likely* clause is only in `timing_aggregate.py`).
* **Round trip.** One `stats` request to the model worker through the file mailbox, timed with `time.perf_counter()` in the control plane. Conditions: idle (no CPU-hog neighbour), limited (neighbour with the red sandbox limits: 1 CPU, 8 busy processes), unrestricted (16 busy processes, no limit). 10 blocks of 100 timed calls per condition per execution after 20 discarded warm-ups (kept in `raw_rtt.jsonl`, flagged), block order shuffled within each repetition, a block counts only if the neighbour was running before and after it. Median and p99 use the nearest-rank rule `sorted[round(p·(n−1))]`. Percentage increase = 100 × (median under contention − idle median) / idle median, pooled samples of the same execution; same for p99; 95% interval by bootstrap over blocks (2000 resamples).

## Results (full discussion: `../../../VALIDATION_ADDENDUM_2026-10-22.md` section 4)

| Setting | Held-out accuracy, 3 executions | p (3 executions) | Pooled n=600 | Fit on other executions | Verdict |
|---|---|---|---|---|---|
| none | 0.795, 0.795, 0.800 | 0.001 each | 0.797 | 0.797 | control: leak detected |
| 100 ms | 0.510, 0.515, 0.545 | 0.43, 0.39, 0.21 | 0.523 | 0.507 | no leak detected (inconclusive as to absence) |
| 250 ms | 0.530, 0.555, 0.495 | 0.30, 0.14, 0.54 | 0.527 | 0.508 | same |
| 500 ms | 0.510, 0.510, 0.495 | 0.40, 0.45, 0.56 | 0.505 | 0.477 | same |

Round trip, median over three executions' idle / limited / unrestricted: 2.59–2.84 / 2.53–2.88 / 3.63–4.16 ms; p99 4.66–5.10 / 4.61–5.15 / 6.75–8.18 ms; unrestricted median +37.5% to +51.7% against idle, limited −4.2% to +2.3%.

**Limits.** Reduction of the classifier from ≈0.80 to ≈0.5 is conclusive for this classifier, stub and payload set; absence of leakage is not shown (n=200 cannot tell accuracy up to ≈0.57 from chance). Ten distinct payloads, label confounded with payload; the stub's latency is a fixed ~40 ms sleep; one weak adversary; one host with a desktop session; RTT is quantised by ~2 ms mailbox polling; "idle" is not a quiet host (host CPU busy 10–47% in idle blocks, from the desktop and the harness's own polling); block-to-block medians vary by about 1 ms; p99 rests on the 10 slowest of 1000 calls.

## Historical timing record (`timing/historical/`)

* `exec1_console_extract.txt`: console output of the earlier execution 1 as captured in the 22 Oct hardening session. **Unverified**: no raw file exists (its output file and scratch state were overwritten by the next run). It ran at 19:48 IST, before `aegis/audit.py` (20:02:15) and `aegis/runs.py` (20:02:54) were edited, so it did not run on the shipped code. `exec1_vs_shipped_timing_eval.diff` shows its script differed from the shipped script only by the provenance stamp. The values 0.545 / 0.595 / 0.515 and 2.72 / 4.62 / 8.23 ms / +70% exist only there.
* `timing_recovered_raw.jsonl`, `timing_execution_2_recovered_raw.jsonl`, `*_reproduction.json`: per-request observations recovered from the surviving scratch state (`var/validation_2026-10-22/timing`, `timing2`) of the two saved earlier executions (`../../validation_2026-10-22/timing.json`, `timing_execution_2.json`, stamped `de2e6271…`), and the re-run of the same analysis with the recorded seeds: every stored accuracy, interval, AUC and p-value is reproduced exactly (8 of 8 settings). Their round-trip results are summaries only. Both are historical measurements of an earlier code hash and are not used for current claims.

## DEMO-001_released: verifying a completed run

`DEMO-001_released/` is a `RELEASED` run of the shipped demo (`scripts/demo_run.py DEMO-001`), produced by the 22 Oct code on a throw-away state directory: 25 audit entries, 3 signed checkpoints, a signed terminal checkpoint (`terminal_anchor.json`), a reviewer-held checkpoint file, the public key. It contains no private key. As in the other bundles, the public key sits next to the evidence for convenience, so this check proves the files are consistent with that key, not that the key is genuine; in a real review the reviewer pins the key out of band.

```bash
cd aegislab        # after scripts/quickstart.sh has created .venv, or in any Python 3.11+ environment with `pip install -r requirements.txt`
.venv/bin/python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released                               # strict: exit 0, "ok": true, "terminal_verified": true
.venv/bin/python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released --run-id DEMO-001 --expect-state RELEASED --expect-events 25   # exit 0

# tamper with a COPY and watch it fail (never edit the shipped bundle)
cp -r evidence/closeout_2026-10-22/DEMO-001_released /tmp/demo-copy
head -n -3 evidence/closeout_2026-10-22/DEMO-001_released/audit.jsonl > /tmp/demo-copy/audit.jsonl
.venv/bin/python -m aegis.verify_cli --bundle /tmp/demo-copy                                                              # exit 1: "log has 22 entries but a signed checkpoint covers seq 24: truncation"
```

**Relation to the submitted bundle.** The deck, website snapshot and video show the 15 Oct `DEMO-001`, which is `evidence/DEMO-001/`: a completed run (`RELEASED`, 25 entries) in the legacy format with no terminal checkpoint. It is unchanged. Strict verification rejects it by design (exit 1: "no signed terminal checkpoint ... legacy checkpoints only"). With `--allow-in-progress` it verifies chain and checkpoint consistency only (exit 0, `terminal_verified: false`, warning "completeness of the log is NOT established"); that is **not** equivalent to verifying a completed run, and the bundle cannot be upgraded without forging a signature. The 22 Oct run in this folder has the same attack pack, defence configuration and policy but different nonces, canary, digests and signing key. `DEMO-001_released_verification_log.txt` records exit codes 0 (genuine), 1 (truncated copy), 1 (edited entry), 1 (truncated copy with the anchor removed), 1 (legacy, strict) and 0 (legacy, `--allow-in-progress`).
