# Final checks of the candidate release (22–23 Oct 2026)

Terminal logs and exit codes of every check, run by `phase1_closeout/tools/validate_candidate.sh` on a **disposable copy** of the candidate release (made with `rsync`, before this folder existed), with the original release, `_baseline/` and `submission/` checked read-only before and after. `EXITS.txt` lists the exit code of every step; a step is correct when its exit code is the expected one:

| Step | Expected exit | Log |
|---|---|---|
| 01 / 20 original release `MANIFEST.sha256` before / after | 0 / 0 | `01_…`, `20_…` |
| 02 / 21 the 22 original evidence-file hashes (`_baseline/evidence_sha256_2026-10-22.txt`) before / after | 0 / 0 | `02_…`, `21_…` |
| 03 / 18 candidate-copy manifest before / after the checks | 0 / 0 | `03_…`, `18_…` |
| 04 complete `scripts/quickstart.sh` (8 stages, installs into a new `.venv`, runs the tests and a new `DEMO-001`) | 0 | `04_quickstart.log` |
| 05 `pytest -q tests` | 0 (144 passed) | `05_pytest.log` |
| 06 `scripts/security_demo.sh` | 0 (33/33, 1 `[LIMIT]`) | `06_security_demo.log` |
| 07 `evaluation/check_claims.py` | 0 | `07_check_claims.log` |
| 08 `evaluation/check_claims.py --full` (also recomputes the 12 permutation p-values from raw data) | 0 | `08_check_claims_full.log` |
| 09, 10 completed `DEMO-001_released`, strict verifier | 0, 0 | `09_…`, `10_…` |
| 11 `VAL-001` genuine | 0 | `11_…` |
| 12 `VAL-001_TAMPERED_truncated_last3` | **1** | `12_…` |
| 13, 14 copies of `DEMO-001_released` with the last 3 entries removed / one entry edited | **1**, **1** | `13_…`, `14_…` |
| 15 legacy `evidence/DEMO-001`, strict | **1** (by design) | `15_…` |
| 16 legacy `evidence/DEMO-001`, `--allow-in-progress` | 0 (completeness not established) | `16_…` |
| 17 five deliberately wrong copies (a document range changed, one raw round-trip edited, a stored metric edited, an unsourced number reintroduced, a required claim removed) run through `check_claims.py` | **1** each | `17_negative_*.log` |
| 19 candidate release manifest (the real candidate, not the copy) | 0 | `19_…` |
| 22 hashes of the two files in `_baseline/` | 0 | `22_…` |
| 23 secret scan of the candidate (private key blocks, key/token files, `var/`, `.venv/`, credential-looking strings) | 0, nothing found | `23_secret_scan.log` |

Paths in the logs are relative to the project folder. The manifest of the released candidate was rebuilt after this folder was added; see the Phase 1 closeout report for that final check.
