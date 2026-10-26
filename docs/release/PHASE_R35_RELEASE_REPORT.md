# Phase R3.5 release report: AegisLab public R3 release

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · 26 October 2026.

Phase R3.5 publishes the Phase R3 hardening through a reviewed pull request with real GitHub CI. It adds no features and
does not change the UI. Fields that depend on an action not yet taken are marked `PENDING_APPROVAL` or `NOT_RUN`.

## 1. Release status

**Status: READY FOR PUSH — APPROVAL REQUIRED.** Local review and gates pass; nothing has been pushed, merged or tagged
on GitHub by this phase yet.

## 2. Git state

| Item | Value |
|---|---|
| Repository | `https://github.com/Invinciblx777/HIH` (public, default branch `main`) |
| Public `main` at the start of R3.5 | `209d386` (merge of PR #4, Phase R2); unchanged since the R3 base |
| Original R3 head | `9516944` (local annotated tag `aegislab-r3-rc1`, not published) |
| R3 commits | `74969d7`, `3a66d76`, `8c783ab`, `ddbfd85`, `9516944` (merge base with `main`: `209d386`) |
| R3.5 commit | the commit that adds this file, on top of `9516944` (CI workflow pins, README console notes, `docs/release/`) |
| R3 pushed before R3.5 | no (`origin` had no `r3/*` branch, no R3 pull request, no workflow run) |
| Remote branch SHA | PENDING_APPROVAL |
| Pull request | PENDING_APPROVAL |
| CI run | PENDING_APPROVAL (see `R35_GITHUB_CI_RESULTS.md`) |
| Merge commit on `main` | PENDING_APPROVAL |
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

PENDING_APPROVAL. The workflow has never run on GitHub. Result and URL will be recorded in `R35_GITHUB_CI_RESULTS.md`.

## 8. Post-merge clean-clone validation

NOT_RUN (depends on the merge).

## 9. Rollback

The release is one pull request. If it must be undone after merge: `git revert -m 1 <merge commit>` on a branch, through
a new pull request. `main` at `209d386` is the last pre-R3 state. Never force-push `main`.

## 10. Human actions

1. Approve pushing `r3/security-hardening` and opening the pull request.
2. After green CI, review and approve the merge.
3. Optionally approve publishing a release tag (not done without separate approval).
4. Submission on Unstop (deadline 28 October 2026, IST) is a team action.
