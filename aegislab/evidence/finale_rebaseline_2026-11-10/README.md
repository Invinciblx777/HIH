# Grand Finale P2 re-baseline, 10 Nov 2026

P2 changed hash-pinned code: `aegis/runs.py`, `aegis/api.py`, `aegis/model_client.py`, `evaluation/llm_common.py`, `evaluation/llm_isolation.py` and others. The change is commit `c018c52` on `finale/p2-rebaseline`, stacked on `finale/p1-public-demo` (`9932cfa`).
- Every earlier evidence folder is untouched. Nothing under `../validation_2026-10-22/`, `../closeout_2026-10-22/`, `../phase2_2026-10-23/`, `../phase3_2026-10-23/`, `../finals_2026-10-22/`, `../DEMO-001/` or `../results.json` was edited, moved or deleted.
- This folder holds:
  - what was **re-measured** on the new code;
  - the **acknowledgement** of the source changes that the saved real-model runs recorded.

## What changed (summary)

| Finding | Change |
|---|---|
| F3: monitoring side channel | The monitoring stream no longer carries the red-chosen `attack_id`. It carries the broker's counter and a digest instead. Before a run is SEALED, only the operator and the reviewer see every event (alerts included). Everyone else sees run-level events only: no sequence numbers, no digests, no per-attack alerts. |
| F5: quickstart | `scripts/quickstart.sh` points to `scripts/start_prototype.sh`. |
| F7: tenant-storage race | Atomic copy plus `os.replace` in `ensure_tenant_storage`. |
| Phase 3 residual | `cache_prompt=true` is refused unless `AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1` is set. The opt-in is recorded in the manifest and the audit log. |
| Item 5: release consistency | A release that fails strict verification after signing now stays RELEASED, consistent with its signature. It is marked unverified and hands nothing out. |

## Re-measured on the new code (`REMEASURED.json`)

`REMEASURED.json` records the commit, the code-tree hash, the host, each command and the sha256 of every raw file. `evaluation/check_claims.py` (Part D) re-reads these files, checks the hashes and checks each security property.

| File | Command (from `aegislab/`, scratch state outside the repository) | Result | Recorded before |
|---|---|---|---|
| `validation/isolation_matrix.json` | `AEGIS_VAR=<scratch> .venv/bin/python evaluation/run_validation.py --out evidence/finale_rebaseline_2026-11-10/validation --runs 30 --seed 1` (98 s, rootless Podman) | 181/181 unauthorized cases denied, 0 succeeded; 0 marker hits in 216 public bodies; 92/92 traversal cases rejected | identical (22 Oct) |
| `validation/audit_tamper.json`, `validation/bundles/` | (same command) | 19/19 tamper categories detected 30/30; clean logs 30/30 accepted, terminal verified 30/30; truncation with only the freeze checkpoint 30/30 detected (fail-closed); CLI 10/10 genuine accepted, 40/40 tampered rejected | identical (22 Oct) |
| `role_matrix_extended.json` | `AEGIS_VAR=<scratch> .venv/bin/python evaluation/phase2_matrix.py --out evidence/finale_rebaseline_2026-11-10/role_matrix_extended.json` (3 s, container-free) | 560 attempts: 419/419 denied, 141/141 allowed, 0 unexpected, 0 secret hits | identical (23 Oct) |
| `e1_e9_rerun/` | `AEGIS_VAR=<scratch> .venv/bin/python evaluation/run_evaluation.py --runs 10 --out evidence/finale_rebaseline_2026-11-10/e1_e9_rerun` (167 s, rootless Podman, stub model) | E2: 150/150 forbidden requests denied, 90/90 connects failed, 240/240 foreign paths absent; E8: 0 occurrences in 864 monitoring events | identical E2 (22 Oct) |

Notes on the table:
- The generated `e1_e9_rerun/RESULTS.md` keeps the harness's own wording, as the 22 Oct copy does: "6 tamper types" and "gap shown by last case".
- Its E7 line uses the old **in-sample** classifier, so it illustrates that measure's instability. It is not a timing result.

Verify the new bundles (they are copies of what the suite published):

```bash
python -m aegis.verify_cli --bundle evidence/finale_rebaseline_2026-11-10/validation/bundles/VAL-001                          # exit 0
python -m aegis.verify_cli --bundle evidence/finale_rebaseline_2026-11-10/validation/bundles/VAL-001_TAMPERED_truncated_last3 # exit 1
```

## Recorded before P2, not re-run here

- **Real-model experiments.** These are `../validation_2026-10-22/model_experiments.json` (M1–M6) and `../phase3_2026-10-23/llm/` (E1–E5, recorded 23 Oct on code tree `sha256:364a4adbc523…`). They need the real model and are planned for finale P3.
  - The Phase 3 runs record the sha256 of their security-relevant sources, and five of those files changed.
  - `SOURCE_DRIFT.json` records each change: the recorded hash, the new hash, the commit, the reason, and per experiment whether and why the change affects what it measured. In every case it does not.
    - The request bodies sent to the model are byte-for-byte the same. The cache-on controls now pass through the explicit opt-in.
    - The broker's model call, canary detection, withholding and red reply are unchanged.
    - The monitoring stream now holds less text.
  - `check_claims.py` accepts the difference only for exactly these new hashes. A further edit fails again.
  - M1–M6 do not record source hashes. The same reasoning applies: the real-model request path is unchanged and only the monitoring text and views changed.
- **Timing.** This covers `../closeout_2026-10-22/timing/` and `../phase2_2026-10-23/contention/`; re-running them takes hours.
  - The change **does** touch `aegis/runs.py`, including `Broker.attack()`. The only differences on that path are the monitor summary written after the padded sleep (a shorter string plus one short digest field) and the read-side `monitor_view`.
  - The padding computation, the defence and model calls and the reply path are byte-identical. The audit and monitor writes still happen after the padded sleep and before the reply, as when the timing was measured.

## Files

| File | What it is |
|---|---|
| `SOURCE_DRIFT.json` | Acknowledged source changes since the saved Phase 3 runs (read by `evaluation/check_claims.py`, list fixed in that file) |
| `REMEASURED.json` | Commit, commands, host and raw-file hashes of the re-measurement |
| `validation/`, `role_matrix_extended.json`, `e1_e9_rerun/` | Raw re-measured results |

The phase's working logs are kept by the team outside the repository and are not needed to check anything here:
- the live F3 marker scan before and after the change;
- the new tests run on the old tree;
- P2L03 run 200 times;
- the drift proof.

The tests that back each change are in the repository: `tests/test_finale_p2_*.py`.
