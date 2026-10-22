# Phase 2 adversarial security evidence (23 Oct 2026)

Everything here was produced by `tests/test_phase2_*.py`, `evaluation/phase2_matrix.py` and `evaluation/timing_closeout.py` run on the Phase 2 code, with the Phase 1 candidate (`release_2026-10-22_rc1`) as the "before" tree. Synthetic payloads, dummy credentials, disposable state directories only. Nothing in `evidence/validation_2026-10-22/`, `closeout_2026-10-22/`, `finals_2026-10-22/`, `DEMO-001/` or `results.json` was touched.

| Path | What it is |
|---|---|
| `before_fix/01_broker_before_fix.txt`, `02_lifecycle_before_fix.txt`, `03_audit_before_fix.txt` | The new tests run against the unmodified Phase 1 code: which attacks succeeded (failing test names) |
| `before_fix/11_poc_mailbox.txt` | Container proof of concept (`phase2/tools/poc_mailbox_attacks.py` in the workspace): a real hardened sandbox plants a link or replaces its mailbox directory; the broker's own write function follows it (Phase 1 layout) or does not (Phase 2 layout) |
| `before_fix/13_before_fix_checks.txt` | Flood growth before and after, the checkpoint-ordering and duplicate-index failures, the regular-expression stall |
| `after_fix/20_after_fix_*.txt` | The same tests on the Phase 2 code, verbose |
| `role_matrix_extended.json` | 560 attempted operations over six lifecycle states, unknown run ids, identity mix-ups, component calls: counts per category |
| `effective_container_settings.json` | What `podman inspect` reported for the red, defence and model workloads of one real run, the flags requested, and the red sandbox's own observations |
| `contention/` | Three reduced executions of the mailbox round-trip comparison (idle, limited neighbour, unrestricted neighbour) with raw samples; `summary.json` reads them |

Reproduce (from `aegislab/`, venv active): `pytest -q tests` (297 tests: 144 from Phase 1 and 153 added in Phase 2); `python evaluation/phase2_matrix.py`; `python evaluation/timing_closeout.py --seed N --runs 4 --rtt-reps 5 --rtt-block 100 --out-dir NEW_DIR`.

Local workspace and scratch paths in the `.txt` logs were replaced by `<workspace>`, `<scratch>` and `<tmp>`; test names, outcomes and counts are unchanged. Raw `result.json` files under `contention/` keep their own `/tmp` state-directory field.

Limits: container-free tests exercise the real broker and run code with the defence runner and model replaced by in-process fakes; the container tests need rootless Podman and the built image and are skipped otherwise. The contention executions are small and were run on a quiet host. Devices (character or block special files) cannot be created by an unprivileged process and were not tested.
