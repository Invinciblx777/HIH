# Phase R3.5 release report: AegisLab public R3 release

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · 26 October 2026.

Phase R3.5 publishes the Phase R3 hardening through a reviewed pull request with real GitHub CI. It adds no features and
does not change the UI. Fields that depend on an action not yet taken are marked `PENDING_APPROVAL` or `NOT_RUN`.

## 1. Release status

**Status at the time of this commit: READY TO MERGE — APPROVAL REQUIRED.** The local review and gates pass. The branch
was pushed with approval, PR #5 is open, and hosted CI passed on the reviewed commit `52db77d`. Nothing is merged or
tagged yet. Merge facts are recorded after the merge, outside this file (see section 8).

## 2. Git state

| Item | Value |
|---|---|
| Repository | `https://github.com/Invinciblx777/HIH` (public, default branch `main`) |
| Public `main` at the start of R3.5 | `209d386` (merge of PR #4, Phase R2); unchanged since the R3 base |
| Original R3 head | `9516944` (local annotated tag `aegislab-r3-rc1`, not published) |
| R3 commits | `74969d7`, `3a66d76`, `8c783ab`, `ddbfd85`, `9516944` (merge base with `main`: `209d386`) |
| R3.5 commit (reviewed) | `52db77d` on top of `9516944` (CI workflow pins, README console notes, `docs/release/`) |
| R3.5 record commit | the commit that fills in these CI results (documentation only) |
| R3 pushed before R3.5 | no (`origin` had no `r3/*` branch, no R3 pull request, no workflow run) |
| Remote branch SHA | `52db77d2ccf390e5af73e86bc56e8654d1e8eec7` at push; it matched the local SHA |
| Pull request | https://github.com/Invinciblx777/HIH/pull/5 (against `main`, mergeable, `main` not protected) |
| CI run | success: https://github.com/Invinciblx777/HIH/actions/runs/40329363729 (PR) and 40329309774 (push) |
| Merge commit on `main` | `7434152` (PR #5 merged 26 Oct 2026 17:38:12 UTC by Invinciblx777; recorded in Phase R4, see section 9) |
| Release tag published | no (tag publication was not requested) |

## 3. What R3.5 changed

| File | Change |
|---|---|
| `.github/workflows/release-gates.yml` | actions pinned by commit SHA; `persist-credentials: false` (R35-01, R35-02 in `R35_SECURITY_PREFLIGHT.md`) |
| `README.md` | console session rules: single-use link, `--link`, End session, local-only warning, cookie limit, release gates; links to the interactive walkthrough and this report |
| `docs/release/*.md` | this report, the security preflight, the CI record and the final judge checklist |

No application code, test, script, UI file, pinned file or evidence file changed in R3.5.

## 4. Local validation on the supported host

Host: Fedora, kernel 7.2.11, rootless Podman 5.8.9 with the sandbox image `localhost/aegislab-sandbox:0.1`,
Python 3.14.8, Node 24.22.0. Run from `aegislab/` on the R3 code (`9516944`) with the R3.5 workflow change in the tree.

| # | Command | Exit | Result |
|---|---|---|---|
| 1 | `bash scripts/release_gates.sh --with-browser --strict` | 0 | 8 PASS, 0 FAIL, 0 SKIPPED: python-syntax (50 files), js-syntax, pytest-container-free (449 passed, 2 skipped = the two browser modules outside `.venv`, 14 deselected), check-claims, check-presentation (157/157), manifest (259 entries OK), publication-scan (0 FAIL, 0 WARN), browser-core (6 PASS) |
| 2 | `.venv/bin/python -m pytest -q -m podman -rs` | 0 | 13 passed, 2 skipped (the same browser modules) |
| 3 | `pytest tests/test_phase4_presentation.py::test_P4D01_judge_demo_passes_and_labels_precomputed_evidence` | 0 | 1 passed (deselected from the container-free gate because it runs `judge_demo.sh`) |
| 4 | `bash scripts/judge_demo.sh` | 0 | 17/17 checks behaved as expected |
| 5 | `bash scripts/security_demo.sh` | 0 | 34/34 checks behaved as expected, plus 1 documented limit (not counted as a pass) |
| 6 | `bash scripts/run_browser_tests.sh --live --require` | 0 | 3 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED (whole live lifecycle in real containers, desktop and phone widths) |
| 7 | `python3 tools/publication_scan.py --repo . --history` | 0 | 0 FAIL, 0 WARN over the index and all history |
| 8 | `podman ps -a` after the runs | — | no `aegis-*` container left |

Together, 1 and 2 plus 3 cover the full pytest suite (449 + 13 + 1 = 463 passed; the 2 browser-module skips are run by 1
and 6 through the browser virtualenv: 6 + 3 = 9 browser tests). After the browser runs the regenerated screenshots were
restored to their committed versions (they differ only in timing).

The R3 figures recorded in `docs/prototype/PHASE_R3_EXECUTION_REPORT.md` (13 live adversarial checks, clean-clone gates)
were not repeated in R3.5 unless listed above; that report remains the record for them.

## 5. Security review

See `R35_SECURITY_PREFLIGHT.md`. Every security-sensitive R3 change was read in code and test form. No release-blocking
or High-severity issue. Two Low CI-workflow items fixed. The R3 residual risks stand: cookies shared across loopback ports,
single local operator, unsigned post-terminal audit records, global login lockout, no slow-body timeout.

## 6. Historical evidence integrity

- `MANIFEST.sha256` unchanged since `209d386`; `sha256sum -c` passes for all 259 entries.
- No file under `aegislab/evidence/`, no Phase 1–4 report and no R0–R3 document was modified by R3.5.
- The R3 historical figures in `docs/prototype/` were not rewritten; R3.5 results are reported here as newer validation.

## 7. Hosted CI

**Passed** on `52db77d`, in the first workflow runs the repository has ever had. Both runs succeeded: release gates 8/8
PASS with 0 skipped, 449 container-free tests and 6 browser tests. Details are in `R35_GITHUB_CI_RESULTS.md`. Hosted CI
does not cover the Podman-dependent checks; section 4 records those.

## 8. Merge and post-merge clean-clone validation

NOT_RUN when this file was committed. The merge needs separate approval. After the merge, the merge SHA and the
clean-clone results go into the PR #5 conversation and the team's handoff. This file is not edited again on `main`, so
it never claims a result that did not exist when it was written.

## 9. Rollback

The release is one pull request. If it must be undone after merge: `git revert -m 1 <merge commit>` on a branch, through
a new pull request. `main` at `209d386` is the last pre-R3 state. Never force-push `main`.

## 10. Human actions

1. Approve pushing `r3/security-hardening` and opening the pull request. Done: approved and pushed on 26 Oct.
2. Review and approve the merge of PR #5. Pending.
3. Optionally approve publishing a release tag (not done without separate approval).
4. Submission on Unstop (deadline 28 October 2026, IST) is a team action.

## 9. Post-merge record (added in Phase R4, 26 Oct 2026)

This section was written after the fact from the public repository; the sections above keep their original wording.

| Item | Value |
|---|---|
| PR #5 | merged 2026-10-26 17:38:12 UTC by Invinciblx777, merge commit `743415223e916d31c43c48f648d31524c8ba1d88` |
| `main` after the merge | `7434152` (no later commits at the time of the R4 check) |
| CI on the merge commit | run 40370478665, `push` to `main`, 17:38:15 to 17:41:04 UTC, job `gates` success, artifact `release-gate-logs` (id 12673006726): `summary: 0 failed, 0 skipped`, pytest-container-free 449 passed / 2 skipped (the two browser modules, Playwright not in `.venv` by design) / 14 deselected |
| Record commit `1cdca1b` | made locally on `r3/security-hardening` after the push and never pushed, so it is not in `main`. Its CI-results text is carried into R4 unchanged in `R35_GITHUB_CI_RESULTS.md` |
| Post-merge clean-clone validation | done in Phase R4 on `7434152`: `docs/release/PHASE_R4_FINAL_REPORT.md` |
| Tag `aegislab-r3-rc1` | still local only (on `9516944`), not published |
| Submission channel | the team states submission is **not** through Unstop; the deadline is 28 Oct 2026 (IST) under the organizer's separate instructions. Item 4 in section 8 is superseded by `docs/release/R4_SUBMISSION_CHECKLIST.md` |

