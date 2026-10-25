# Validation record, 25 Oct 2026 (Phase R0)

What was run, on what, and with which result. Nothing here is copied from an earlier phase.

## Environment

One host: Fedora Linux 44, kernel 7.2.11, Python 3.14.8, Podman 5.8.9 rootless. Started 2026-10-25T17:52:36Z.
Each run starts from `git archive HEAD` of the commit under test, extracted into an empty directory, so untracked files cannot influence it. Script: `round2/tools/validate_repo.sh` in the team workspace (not part of this repository); the steps are the commands below.

## Before: public `main` at `a545e86` (prototype at the repository root)

| Step | Command (from the checkout) | Exit | Result |
|---|---|---|---|
| quickstart | `bash scripts/quickstart.sh` | 1 | **FAIL** at stage `tests`: 1 failed, 344 passed (`test_P4D01_judge_demo_passes_and_labels_precomputed_evidence`) |
| tests | `.venv/bin/python -m pytest -q tests` | 1 | **FAIL**, same test |
| security demo | `bash scripts/security_demo.sh` | 1 | **33/34**: "saved LLM experiment runs agree with their raw observations…" failed, cause `PHASE3_LLM_SECURITY_REPORT.md … report missing` |
| judge demo | `bash scripts/judge_demo.sh` | 1 | **16/17**, same check |
| claims checker | `.venv/bin/python evaluation/check_claims.py` | 1 | **crash**: `FileNotFoundError … Tech_Mavericks_AegisLab_Submission.pptx` |
| strict verification of shipped bundles, tamper rejection | `python -m aegis.verify_cli …` | 0 / 1 as expected | pass (the two tamper cases on the quickstart bundle were vacuous because quickstart stopped before creating it) |

Cause: the checkers read the release-level reports and the deck from the parent directory of the prototype (the release-package layout). The public tree had no parent package, so those files were missing. The code itself was fine.

## After: this layout, commit `d130b78`

The prototype is unchanged in `aegislab/`; code tree hash `sha256:980372c7c18981caacfa116b3f2d1e045ff94d752e5ad91adb0dd1b2fef9a930` (48 files) before and after.

| # | Command (run from `aegislab/` unless noted) | Expected | Exit | Result |
|---|---|---|---|---|
| 00 | `sha256sum -c MANIFEST.sha256 --quiet` (repository root) | 0 | 0 | 442 / 442 rc4 files match |
| 01 | `bash scripts/quickstart.sh` | 0 | 0 | 8 / 8 stages PASS, 74 s (includes image build check and the full test suite) |
| 02 | `.venv/bin/python -m pytest -q tests -p no:cacheprovider` | 0 | 0 | **345 passed**, 2 deprecation warnings, 61 s |
| 03 | `bash scripts/security_demo.sh` | 0 | 0 | **34 / 34** checks plus 1 documented `[LIMIT]` (key holder who replaces every retained copy) |
| 04 | `bash scripts/judge_demo.sh --record …` | 0 | 0 | **17 / 17** checks |
| 05 | `.venv/bin/python evaluation/check_claims.py` | 0 | 0 | 14 / 14 quoted numbers, 72 / 72 timing, 48 / 48 Phase 3 (134 / 134) |
| 05b | `.venv/bin/python evaluation/check_presentation.py` | 0 | 0 | 157 / 157 |
| 07 | `verify_cli --bundle var/quickstart/bundles/DEMO-001 --run-id DEMO-001 --expect-state RELEASED` | 0 | 0 | fresh bundle verifies strictly |
| 08 | `verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released …` | 0 | 0 | shipped released bundle verifies |
| 09 | `verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001 …` | 0 | 0 | verifies |
| 10 | same, copy of the fresh bundle with the last 3 entries removed | 1 | 1 | rejected (truncation) |
| 11 | same, copy with one entry's data edited | 1 | 1 | rejected |
| 12 | `verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3 …` | 1 | 1 | rejected |
| 13 | `verify_cli --bundle evidence/DEMO-001 …` (15 Oct legacy bundle, strict) | 1 | 1 | rejected by design (no terminal checkpoint) |
| 14 | `python3 tools/publication_scan.py --history` (repository root) | 0 | 0 | 451 files in the index and 38 further history blobs: 0 FAIL, 0 WARN with 7 reviewed allowlist rules |
| 15 | `sha256sum -c MANIFEST.sha256 --quiet` after all steps | 0 | 0 | 442 / 442 unchanged |
| 16 | `.venv/bin/python evaluation/check_claims.py --full` | 0 | 0 | 14 / 14, 84 / 84 timing (permutation tests recomputed from raw per-request files), 48 / 48 |
| 17 | tamper snippet from `docs/JUDGE_GUIDE.md` section 4 | 1 | 1 | rejected: "entry content does not match its hash" |

## Not run, and why

- **Real-model experiments** (`evaluation/llm_isolation.py`, `evaluation/model_experiments.py`): not re-run. They need a local llama.cpp `llama-server` and the Qwen2.5-0.5B GGUF (not in the repository) and take about 3.5 hours. The demos and `check_claims.py` recompute their figures from the saved raw files and check source hashes; that check ran (48 / 48).
- **Timing and contention measurements** (`evaluation/timing_closeout.py` and friends): not re-measured; their saved raw data are re-analysed by `check_claims.py --full` (step 16).
- **Other hosts, distributions, GPU**: not available. Results hold for this one Fedora host.
- **Video and audio**: not inspected in R0. No human has listened to the pitch video.
