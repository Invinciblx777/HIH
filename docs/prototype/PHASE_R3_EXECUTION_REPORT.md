# Phase R3 execution report: security hardening, reliability and judge-ready release

Date: 26 October 2026 (IST). Branch: `r3/security-hardening` (local, not pushed). Verdict: section 16.

## 1. Baseline Git revision

- Repository `round2/work/HIH`, remote `origin` = `github.com/Invinciblx777/HIH`. `git fetch` on 26 Oct: `main` =
  `origin/main` = `209d386` (merge of PR #4, `r2/live-security-lab`). Working tree clean, no stash.
- The five R2 commits exist as reported: `57a65cd` (backend), `0129465` (UI), `39b64fc` (tests), `0224814` (docs),
  `b066e47` (SHAs in report), all reachable from `main`.
- R3 branches from `209d386`.

**Mismatches between the reported R2 state and the source:**

| Reported | Actual |
|---|---|
| "The public repository may still lack the R2 changes"; R2 report says "local only, not pushed" | R2 **is public**: merged into `origin/main` by PR #4 (`209d386`) after the R2 report was written. |
| R2 limitation "body limit by Content-Length" | Confirmed, and worse than stated: an unauthenticated chunked body of any size was read and parsed in full (R3-01). |
| PROTOTYPE_GUIDE: "Without `AEGIS_CONSOLE_LAUNCH_CODE` … keeps it in `var/console/console/launch_code`"; 403 page: "the code is also in $AEGIS_VAR/console/launch_code" | With the launcher (which set the environment variable) no file was written, so the 403 page pointed to a file that did not exist. R3 makes the file the single source of truth. |
| Probe UI: refusal on a released run "is not logged" | The control plane does record it, unsigned, in `post_terminal.jsonl` (R3-05). |

Baseline checks on `209d386` (before any change): `.venv/bin/python -m pytest -q -rs` → **414 passed, 1 skipped**
(browser module, no Playwright), exit 0, 70.9 s.

## 2. R2 features verified

Verified by running them, not by reading the report: operator session (launch link, HttpOnly SameSite=Strict cookie,
CSRF, Origin/Host checks), server-held role tokens, stepwise lifecycle, real rootless Podman execution, the four
scenarios, the request probe, the signed audit-log view, strict verification, disposable and in-memory tamper suites, the
graph overlay, the execution-mode labels, start-up recovery of interrupted runs. Evidence: the R2 tests still pass
(sections 7 and 8), the live browser flow ran end to end on R3 code, and the live adversarial checks in section 11.

## 3. Confirmed security findings

Full table with reproduction, impact, fix, regression test and residual risk: `docs/prototype/R3_SECURITY_REVIEW.md`.

| ID | Severity | Summary |
|---|---|---|
| R3-01 | Medium | Body limit bypass with chunked / length-less bodies; unauthenticated memory exhaustion (8 MiB reproduced, any size possible) |
| R3-02 | Medium | Launch code reusable for the process lifetime, no expiry |
| R3-05 | Medium (UI integrity) | Post-release refusals reported as "not logged"; post-close records invisible |
| R3-03 | Low | Login did not end the browser's previous session |
| R3-04 | Low | Freeze/start answered 503 with host status before checking authorisation |
| R3-06 | Low | Duplicate create requests created extra runs |
| R3-07 | Low | Symbolic links in lab bundles followed by verifier, tamper copy and digests |
| R3-08 | Low | Verifier launch failure → 500; inconclusive status verification cached for 1 h |
| R3-09 | Low | Concurrent tamper records could overwrite each other |
| R3-10 | Info | Early refusals lacked security headers (incl. `no-store`) |
| R3-11 | Info | Browser tests not reproducible; skips not classified |

No High finding. No finding exposed a role token, the signing key, a canary or sealed data.

## 4. Fixes implemented

- **Request bodies** (`console.py`, `BodyLimit`): plain ASGI middleware, outermost. It refuses a declared
  `Content-Length` over 256 KiB, a malformed or conflicting one (400), and a body whose **received bytes** pass 256 KiB
  (413), before any handler runs. The body is buffered (at most 256 KiB) and replayed to the app, so the limit also holds
  for handlers that never read their body (an oversized `freeze` no longer freezes). Refusals send `Connection: close`.
  The old `Content-Length` check in `guard` was removed.
- **Operator session** (`lab_session.py`, `console.py`, launcher): single-use launch code replaced atomically (0600)
  under the lock that compares it; 2 h expiry; `issue()` for the launcher and `--link`; login ends the presented session;
  `end()` compares in constant time; freeze/start authorise first.
- **Lifecycle**: optional `X-Aegis-Idempotency-Key` on create, scoped to the caller, bounded (256 entries), replay
  flagged `replayed: true`; the UI sends one key per click.
- **Audit honesty**: probe returns `recording` (`audit_chain` / `post_terminal` / `counted_only` / `not_recorded`) and the
  post-close entries; the audit endpoint returns `after_close`; nothing is appended to or re-signed in a closed chain.
- **Evidence**: symlink refusal (verify, tamper, download, bundle listing); `OSError` from the verifier → no verdict;
  shipped status cached only when conclusive; malformed tamper input → 409; result numbering under a lock.
- **UI** (`console.js`, `index.html`; no redesign): *End session* link in the header (existing `linkbtn` style);
  idempotency key per Create; honest probe and audit-log wording; "No verdict" instead of "Rejected" when the verifier
  gave no result.
- **Launcher**: `--link`; issues the code into the state file; unsets `AEGIS_CONSOLE_LAUNCH_CODE`.

## 5. Files changed

Modified: `aegislab/aegis/console.py`, `aegislab/aegis/lab_session.py`, `aegislab/scripts/start_prototype.sh`,
`aegislab/web/console/console.js`, `aegislab/web/console/index.html`, `aegislab/tests/browser/test_console_browser.py`,
`.gitignore` (root: `.venv-browser/`), `docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`, `docs/prototype/PROTOTYPE_GUIDE.md`.

New: `aegislab/tests/test_r3_hardening.py`, `aegislab/tests/browser/conftest.py`,
`aegislab/tests/browser/test_console_browser_core.py`, `aegislab/requirements-browser.txt`, `aegislab/constraints.txt`,
`aegislab/scripts/run_browser_tests.sh`, `aegislab/scripts/release_gates.sh`, `.github/workflows/release-gates.yml`,
`docs/prototype/PHASE_R3_EXECUTION_REPORT.md`, `docs/prototype/R3_SECURITY_REVIEW.md`,
`docs/prototype/R3_JUDGE_RELEASE_CHECKLIST.md`, `docs/prototype/screenshots/r3/*.png` (31).

Not modified: every file in `MANIFEST.sha256` (259 entries verify; `aegislab/.gitignore` was briefly edited, caught by the
manifest gate and restored), `aegis/api.py`, `runs.py`, `evidence.py`, `verify_cli.py`, all evidence under
`aegislab/evidence/`, the R2 screenshots, rc1–rc4, the submission files.

## 6. New tests

`aegislab/tests/test_r3_hardening.py`, **49 tests**, container-free (in-process fake workloads for the broker; real
control plane, gates, audit log, signing, verifier subprocess; 5 of them against a real `uvicorn` on a loopback socket):

- body limit at the ASGI layer (streamed over-limit body stops being read after the first chunk past the limit; body at
  the limit replayed intact; malformed, negative, list-valued and conflicting `Content-Length`; client disconnect);
- body limit through the app (declared and streamed oversize during an authenticated session leave no run and keep the
  session; endpoints that do not read their body; mounted control plane; small chunked body accepted; malformed JSON 422
  without a traceback or token);
- real server, raw socket: 4 MiB chunked → 413 + `Connection: close`; declared oversize; misleading `Content-Length`
  (20 declared, 600 kB sent); 12 repeated oversized requests with the session intact; chunked small body; foreign Host;
- session: single use, 8-thread concurrent use → exactly one session, expiry, `--link` invalidation, environment code
  single use, planted id ignored, previous session ended, CSRF bound to its session, idle and absolute expiry,
  `no-store` and `no-referrer`; authorisation before host status;
- lifecycle: idempotency (incl. key scoped per caller), 8 concurrent duplicate creates → one run, 6 concurrent starts →
  one broker, unsupported transitions leave the state, release twice;
- audit: signed-chain refusal on SEALED, unsigned post-terminal refusal on RELEASED with audit log and vault
  byte-identical and strict verification still passing, unlogged requests reported as not recorded;
- evidence: symlinked file and directory, verifier that cannot start, 6 exit-code/verdict combinations, malformed
  bundle, status cache, 4 concurrent tamper demonstrations, bundle ids are registry keys.

**Run against the R2 code** (`209d386` tree with only this test file added): **30 failed, 19 passed**. The 30 failures are
the fixed defects; the 19 passing tests guard behaviour that was already correct (log:
`r3_tests_on_r2_baseline.log` in the gate logs, section 13).

Browser: `tests/browser/test_console_browser_core.py` (6 tests, container-free) and the extended
`tests/browser/test_console_browser.py` (3 tests, live).

## 7. Regression results

Integration gate on `8c783ab` (the code of this release; later commits change documentation only), 26 Oct 2026
17:14 IST, Fedora kernel 7.2.11-200.fc44, Podman 5.8.9 rootless, Python 3.14.8, `PYTHONDONTWRITEBYTECODE=1`:

| Command (from `aegislab/`) | Result | Exit |
|---|---|---|
| `.venv/bin/python -m pytest -q -rs` (includes podman tests) | **463 passed, 2 skipped** (both: browser modules, `SKIPPED (dependency missing): playwright is not installed in .venv`), 72 s | 0 |
| `.venv/bin/python -m pytest -q -rs -m podman` | 13 passed, 2 skipped (same two), 450 deselected | 0 |
| `bash scripts/judge_demo.sh` | 17/17 checks behaved as expected | 0 |
| `bash scripts/security_demo.sh` | 34/34 checks, 1 documented limit (not counted) | 0 |
| `.venv/bin/python evaluation/check_claims.py` | 14/14, 72/72, 48/48 (134 checks) | 0 |
| `.venv/bin/python evaluation/check_presentation.py` | 157/157 | 0 |
| `sha256sum --quiet -c MANIFEST.sha256` (repo root) | 259 entries OK | 0 |
| `python3 tools/publication_scan.py --repo ..` | 0 FAIL, 0 WARN | 0 |

414 (R2) + 49 (R3) = 463. `check_claims.py --full` (timing permutation re-run) was not run in R3: no timing code or
evidence changed.

Container-free gates as hosted CI would run them, simulated locally with a stand-in `podman` that always fails:
`bash scripts/release_gates.sh --with-browser --strict` → 8 PASS, 0 FAIL, 0 SKIPPED (python-syntax, js-syntax,
pytest-container-free 449 passed / 2 skipped / 14 deselected, check-claims, check-presentation, manifest,
publication-scan, browser-core). The same command inside a **fresh clone** (new `.venv` and `.venv-browser`, Playwright
and Chromium installed by the runner) also gave 8 PASS, 0 FAIL, 0 SKIPPED. The workflow itself has **not run on GitHub**
(nothing pushed).

## 8. Browser-test results

Pinned set-up: `requirements-browser.txt` (Playwright 1.64.1, Chromium build 1248), `.venv-browser`, runner
`scripts/run_browser_tests.sh`.

| Command | Result | Exit |
|---|---|---|
| `bash scripts/run_browser_tests.sh --require` (container-free) | PASS 6, FAIL 0, SKIPPED 0, BLOCKED 0 | 0 |
| `bash scripts/run_browser_tests.sh --live --require` (real containers) | PASS 3, FAIL 0, SKIPPED 0, BLOCKED 0, 26 s | 0 |

Coverage against the brief: login (1), logout (2), invalid launch code (3), run creation (4), defence selection (5),
freeze (6), real sandbox execution (7), allowed operation (8: reviewer release, artifacts read), denied operations (9),
audit inspection (10), signed evidence verification (11), tamper rejection (12), refresh during execution and after login
(13), error handling (14: oversized/malformed request from the page, unavailable live mode, unreachable backend), desktop
and phone layouts (15: no horizontal overflow on 7 pages at 1440 × 900 and 390 × 844). Also: single-use link refused
on second use, post-release refusal shown as unsigned, `--link` login. Screenshots: `docs/prototype/screenshots/r3/`
(`01`–`10b` live flow, `c01`–`c06` container-free, `m*`/`cm*` phone).

Harness note: Chromium does not report an upload that the server cut off with 413 as finished, which blocks Playwright's
network-idle wait on that tab; the page itself receives the 413 normally. The test continues in a fresh tab.

## 9. Podman execution results

Real rootless containers (Podman 5.8.9, `localhost/aegislab-sandbox:0.1`): the podman-marked tests (13 passed), the
judge and security demos, the live browser flow (LAB-001 created, frozen, executed, sealed, scenarios, released,
verified, tampered copy rejected), and the live adversarial checks below.

## 10. Evidence verification results

- Live LAB-001 bundle (browser flow and adversarial run): strict verification exit 0, `matches_expectation: true`,
  broker key pinned, terminal hash pinned.
- Tampered disposable copies: `edit_event` (browser), `truncate_tail` (adversarial), `rehash_chain` (container-free
  browser, shipped DEMO-001) → exit 1, rejected; originals byte-identical.
- Shipped VAL-001-TAMPERED → exit 1, as expected. In-memory suite 12 of 12, stored log unchanged.
- Historical evidence unchanged: `MANIFEST.sha256` verifies; no signature was regenerated.

## 11. Startup and recovery results

**Clean checkout** (`git clone --branch r3/security-hardening` of this repository into a scratch directory, new `.venv`):
`start_prototype.sh --check` exit 0, `Mode: LIVE` (7 s); `--reset --port 8471` printed the link; read-only without it;
link → 303 to `/#/lab`, session authenticated with CSRF; same link again → 403 *invalid or already used launch code*;
`--link --port 8471` → new link → 303; status `live`, `STUB MODEL`, shipped bundle exit 0; SIGINT → launcher stopped,
port free, no lab containers, clean `git status`. Total 10 s. The release gates were also run inside that fresh clone
(section 7: 8 PASS).

**Live adversarial QA** (real console, real containers, 13/13 checks):

| Check | Observed |
|---|---|
| 6 parallel creates with one idempotency key | 1 run (`LAB-001`) |
| 4 parallel starts | one 200, three 409 |
| release twice | second 409, run stays RELEASED |
| post-release refusal | `recording: post_terminal`, no signed entry |
| strict verify / tampered copy | exit 0 / exit 1, original unchanged |
| red container killed mid-run (`podman kill`) | run SEALED with `complete: false`, 3 of 10 evaluated; chain intact |
| console killed (SIGKILL) mid-run, restarted | run FAILED, `verify_run` ok and terminal-verified, its 3 containers removed, release refused (409) |
| sessions after restart | old cookie no longer authenticated |

## 12. Remaining limitations

See `R3_SECURITY_REVIEW.md` section 6 (RR-1 to RR-11). The most relevant for a judge demo: cookies are not isolated by
port on 127.0.0.1 (use a dedicated browser profile); one local operator, not multi-user authentication; post-release
refusals are unsigned by design; the model is the deterministic stub; real-model results are precomputed; an incomplete
run (killed container) can still be released and is labelled incomplete; the CI workflow has not run on GitHub yet; the
judge and security demo scripts (pinned) leave their disposable state directories in `/tmp`.

## 13. Release candidate status

Candidate **`aegislab-r3-rc1`**: local annotated tag on the final R3 commit, plus a `git archive` tarball and SHA-256
list in `round2/candidates/r3_rc1/` (outside the repository), with the gate logs of this report. Not pushed, not
merged, not promoted. Earlier candidates and reports were not copied or re-certified.

## 14. Current branch and commits

Branch `r3/security-hardening`, based on `209d386`:

| SHA | Content |
|---|---|
| `74969d7` | backend: body limit, launch code, idempotency, audit honesty, evidence hardening, `test_r3_hardening.py` |
| `3a66d76` | console UI |
| `8c783ab` | pinned browser tests, release gates, CI workflow, R3 screenshots |
| (docs) | this report, security review, checklist, walkthrough and guide updates |

## 15. Remote status

`origin/main` = `209d386` (includes R2). `r3/security-hardening` exists only locally. Nothing was pushed, merged, tagged
remotely or deployed.

## 16. Verdict and next actions

Definition of done: UI works and keeps its design (screenshots); operator authentication protected and strengthened;
streaming cannot bypass the body limit (raw-socket test on a real server); authorisation boundaries hold (R2 + R3 tests,
live probe); a real live lifecycle passed (browser and adversarial runs); allowed and denied operations behave as
expected; the audit UI reports exactly what was recorded; verification fails closed; tampered evidence rejected; original
evidence unchanged; browser tests reproducible and classified; all regression checks pass; no High finding open; the
judge walkthrough is documented and was followed by the browser test; the release can be reviewed for publication.

**Verdict: PASS — HARDENED PROTOTYPE VERIFIED**, with the residual risks of `R3_SECURITY_REVIEW.md` section 6 documented.

Next actions (need a human): review the diff and the security review; approve pushing the branch and let the
`release-gates` workflow run on GitHub; approve the PR into `main`; re-run checklist A and B on the merge commit;
decide about the tag. Phase R4 was not started.
