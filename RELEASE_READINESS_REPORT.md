# AegisLab: release-readiness report (22 Oct 2026, finals push)

> **Phase 4 note (23 Oct 2026):** the deck, PDF, video, captions, voice-over, storyboard and Judge Q&A were regenerated in the Phase 4 candidate and no longer carry the figures below. Figures in this report are those of its own date; `README_FIRST.md` and `PHASE4_PRESENTATION_REPORT.md` describe the current package.


Team Tech Mavericks · Hack in Hills ’26 · Track 04 (Bayora). No score or placement is implied. Nothing was deployed, pushed or published.

> **Update, Phase 1 closeout (22–23 Oct 2026):** the timing figures below were replaced by three fresh, fully recorded executions (`VALIDATION_ADDENDUM_2026-10-22.md` section 4 and section 9; evidence in `aegislab/evidence/closeout_2026-10-22/`). Rows that quoted the earlier timing numbers were corrected in place; sentences describing what "this pass" did describe the finals push as it was.

> **Update, Phase 2 (23 Oct 2026):** the code changed (broker mailbox, lifecycle locking, verifier options, defence-runner time budget); the test suite is now 297 tests and the code tree hash is new. Counts such as "144 passed" below describe the finals push and Phase 1 as they were. See `PHASE2_SECURITY_REPORT.md`.

## 1. What this pass did, and what it did not re-run

An earlier pass on 22 Oct already hardened the code and produced `aegislab/evidence/validation_2026-10-22/` (see `VALIDATION_ADDENDUM_2026-10-22.md`). This pass re-validated that state and closed the remaining consistency gaps.

**Re-executed in this pass (after the final code change):** `pytest -q tests` (144 passed); clean-copy `scripts/quickstart.sh` (8/8 stages, exit 0, 32 s); `scripts/security_demo.sh` on the working tree and on the clean copy (33/33 checks, 1 documented `[LIMIT]`, exit 0); `evaluation/check_claims.py` (17/17 at that time; extended in the closeout); byte check of the 22 original evidence files (all match `_baseline/evidence_sha256_2026-10-22.txt`).

**Not re-run in this pass:** the 30-run audit tamper sweep, the 212-case access matrix, the timing experiments, the real-model experiments M1–M6 and the E1–E9 re-run. Their numbers are the recorded 22 Oct results, produced by the earlier code hash `de2e6271…` (the tree hash is now `6133ff0a…`; the changes since are confined to the demo script and the new checker, section 8 of the addendum). Treat them as measured by the earlier code, not re-measured.

## 2. Changes made in this pass

| File | Change | Why |
|---|---|---|
| `Tech_Mavericks_AegisLab_Submission.pptx` / `.pdf` | Slides 2, 3, 6, 7 and speaker notes updated to 22 Oct figures; slide 7 footer states date, host, model and limits | The deck still quoted 0/30 truncation, 0.80 → 0.57 timing, 13 tests and 4 ms, contradicting the addendum. Originals kept in `../_baseline/` |
| `aegislab/scripts/security_demo.py` | Timing line shows every saved execution (finals push; the closeout points it at the new executions) not one; pre-cleans leftover `aegis-demo-s1*` containers | The old line showed only the most favourable execution; a crashed demo made the next run fail |
| `aegislab/evaluation/check_claims.py` (new) | Recomputes 17 headline numbers from raw JSON (closeout: timing rows recomputed from the raw per-request files and checked against the documents) | Answers "why trust your numbers" mechanically |
| `aegislab/evidence/finals_2026-10-22/` (new) | Saved output of the demo and the checker (fallback evidence from real runs) | Judge fallback if the live demo cannot run |
| `Judge_QA.md` | Section answering the 18 hard questions with evidence pointers | Judge preparation |
| `README_FIRST.md`, `VALIDATION_ADDENDUM_2026-10-22.md`, validation `README.md` | Status per deliverable, hash change, erratum | Keep documents consistent |
| `Voiceover_Script.txt`, `Storyboard_Timestamped.txt` | Erratum header | The 15 Oct video's last validation sentence is historical |

## 3. Six-objective evidence matrix

| # | Objective | Executed evidence (file) | Tested count | Remaining gap |
|---|---|---|---|---|
| 1 | Isolation without breaking function | `e1_e9_rerun/results.json` E2; `closeout_2026-10-22/timing/` RTT; full pipeline runs | 150/150 forbidden broker requests denied, 90/90 connects failed, 240/240 foreign paths absent; RTT idle median 2.59–2.84 ms (n=1000 per execution, three executions); 144 tests; real-model run through the same broker | Shared host kernel; unrestricted CPU neighbour +37.5% to +51.7% RTT median; cpuset pinning not available; one host |
| 2 | Prevent direct and indirect leakage | `isolation_matrix.json`; `model_experiments.json` M4/M5; `closeout_2026-10-22/timing/` | 181/181 denials, 0 unauthorized successes, 0 marker hits in 216 bodies; 0 hits in 270 real-model responses and 120 monitor events; 92/92 traversal rejected | Refusals and timing still a channel: unpadded 0.80, 250 ms inconclusive (0.495–0.555), +198 to +201 ms cost; broker and defence runner see payloads; cache/memory-bandwidth channels untested |
| 3 | Verifiable, tamper-evident audit | `audit_tamper.json`; `bundles/`; demo step 6 | 19 categories × 30 runs all 30/30 detected; clean 30/30 accepted; truncation 0/30 → 30/30; CLI 10/10 accepted, 40/40 rejected; demo: 12 modes on copies, original byte-identical | Key theft plus replacing every retained copy verifies (`[LIMIT]`); vault and anchor are copies, not separate trust domains, unless relocated; broker can sign false entries; compromised verifier |
| 4 | Deployability on standard infrastructure | `scripts/quickstart.sh`; `Containerfile` | Clean-copy run: 8/8 stages, 32 s; failure paths (no podman, failing test) exit 1 | One host and distribution (Fedora, Podman 5.8.9); Docker and Kubernetes not tested; base image was cached |
| 5 | Demonstrate LLM-native threats | `model_experiments.json` M1–M6; E4 | Real 0.5B model: 0/80 and 0/80 canary leaks, controls detect (17/20, 20/20, 20/20); 0/20 contamination vs control 17/20; cached tokens 162 vs 0; failure runs end `FAILED` with verifying checkpoint; stub: 0/20 vs control 9/10 | CPU only, one small model; no GPU, KV-cache memory or hardware side channel; zero leaks is an upper bound (≤3.7% at 95%) |
| 6 | Transparent residual risk | `THREAT_MODEL.md`; addendum; demo step 7 | 12 threat rows with attacker, mitigation, experiment, result, residual, next step; negative and unstable results kept | Some residuals have no experiment (kernel/runtime escape, key theft beyond the demo) |

## 4. Final acceptance criteria

| Criterion | Status |
|---|---|
| Existing functionality preserved | Yes: 144/144 tests, quickstart, demo pass |
| Original 22 evidence files unchanged | Yes: all 22 match the baseline hash list after final changes |
| Final test suite | `pytest -q tests`: 144 passed, 0 skipped, 1 deprecation warning (starlette/httpx) |
| Quickstart end to end | Yes, clean copy of the final tree, 8/8 stages, exit 0, 32 s; same host only |
| DEMO-001 reaches expected terminal state | Yes: `RELEASED`, terminal checkpoint verified (quickstart stage 6) |
| Valid evidence passes independent verification | Yes: `verify_cli` on `bundles/VAL-001` and on the completed `closeout_2026-10-22/DEMO-001_released` exits 0 (10/10 genuine at CLI level) |
| Tampered and truncated evidence rejected | Yes under the documented trust model: 19 categories × 30; demo 12/12 modes; CLI 40/40 |
| Role-boundary negative tests | Yes: 181/181 denials in the matrix; `tests/test_isolation.py` |
| Real-model results from genuine execution | Yes: llama.cpp b11819 CPU + Qwen2.5-0.5B Q4_K_M, recorded in `model_experiments.json`; not re-run in this pass |
| Timing claims have baselines and sample counts | Yes: n=100+100 per setting per execution, chance 0.50, held-out, CI, AUC, permutation p, three complete executions with raw data and source hashes (an earlier first execution with no raw file is historical and unused) |
| Six objectives have evidence-and-gap mapping | Yes: section 3 |
| Presentation and pitch agree with the implementation | **Deck and PDF: yes. Video, captions, voiceover, storyboard: no**, they are the 15 Oct versions with an erratum (blocker: no ffmpeg, browser renderer or speech model on this host). The video understates (it does not claim the truncation fix) |
| Final commands and recovery documented | Yes: section 6 |
| No public deployment or remote publication | Confirmed: nothing deployed or pushed |
| Weaknesses documented | Yes: sections 3 and 5 |

## 5. Three risks a judge is most likely to probe

1. **Trusted broker and single host.** One compromise defeats isolation and can sign false entries; vault and anchor are separate copies, not separate trust domains.
2. **Timing and refusal channel.** Reduced, not shown removed: 250 ms padding was inconclusive across three fresh executions, with a +198 to +201 ms price, one weak classifier and a constant-latency stub.
3. **LLM-native claims scope.** One 0.5B model on CPU; no GPU or KV-cache memory test; zero leaks is an upper bound. Also: the video and website snapshot lag the deck.

## 6. Commands

```bash
cd aegislab
scripts/quickstart.sh                  # venv, deps, image, 144 tests, DEMO-001, verification (add --serve for the console)
scripts/security_demo.sh               # fresh state, a few seconds once the image is built; --pause waits for Enter between steps
.venv/bin/python evaluation/check_claims.py
.venv/bin/python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001                          # exit 0
.venv/bin/python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3 # exit 1
.venv/bin/python -m pytest -q tests
```

Recovery: if a demo crashed, rerun it (it removes leftover `aegis-demo-s1*` containers itself); `podman ps -a` shows any stray container. Saved fallback output of a real run: `aegislab/evidence/finals_2026-10-22/security_demo_output.txt`. Never write into `aegislab/evidence/` root (the harness refuses). Any edit to `.py/.sh/.json` under `aegis/ sandbox/ evaluation/ scripts/ tests/ samples/` changes the code hash stamped in the result files.

## 7. Skipped and why

| Item | Reason |
|---|---|
| Regenerating the video, captions, voiceover | No ffmpeg, Playwright/Chromium or Kokoro model on this host; a half-rebuilt video would be worse than an annotated historical one |
| New real-model or timing runs | Timing was re-run in the Phase 1 closeout (three executions); real-model runs were not repeated (recorded 22 Oct runs exist, the hardware is the same, no code under test changed) |
| Reviewer "why did verification fail" mode | Already present: the verifier prints the specific failure (e.g. "log has 28 entries but the terminal checkpoint binds 31: truncation"), shown in demo step 6 |
| Resource-interference experiment | Measured (RTT idle / limited / unrestricted neighbour, n=1000 per condition per execution, three executions) |
| Docker/Kubernetes run, second host | Not available; stated as untested |

Differentiator chosen: `check_claims.py`, a mechanical threat-to-evidence trace for the quoted numbers (objective 6 and 3: it lets a judge see that deck, report and raw data agree). It does not add a security control.

## 8. Submission directory

The working tree is the `submission/` directory next to the release folders (not packaged). A hygienic copy without `.venv/`, `var/` (throw-away signing keys), `__pycache__` and the LibreOffice lock file is the release folder with its `MANIFEST.sha256` (verify with `sha256sum -c MANIFEST.sha256` from inside it). Of the 22 baseline-hashed files, the 7 under `aegislab/evidence/` are in the release copy and verified byte-identical there; the other 15 are runtime copies under `var/runs/DEMO-001/` and stay only in the working tree (verified identical there). This report: `RELEASE_READINESS_REPORT.md` in the release root.
