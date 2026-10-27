# Phase R4.5 final report: prototype freeze, final video and release preparation

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · 27 October 2026 (IST).

Status words: **VERIFIED** (a command ran and its output is kept), **REPORTED_ONLY**, **NOT_RUN**, **PENDING**,
**HUMAN_APPROVAL_REQUIRED**, **HUMAN_CONFIRMATION_REQUIRED**.

## 1. Verdict

**ENGINEERING COMPLETE — HUMAN APPROVALS PENDING.**

The last open UI observation (phone page shifted sideways) was reproduced, explained and fixed with a regression test
that fails before and passes after. A clean clone of the fix commit passed every gate. A new final video was recorded
from that clean clone, from a real live-sandbox run, and passed automated media and secret checks; no person has watched
it yet. The branch is local and unpushed; no PR was opened, nothing was merged, uploaded, posted or submitted.

## 2. Git state

| Item | Value | Status |
|---|---|---|
| Public `main` at start | `c46df2bdd8885ae005af38537f3c01ac50769585` = merge of PR #6 (`r4/final-prototype` `0d124d2`), 26 Oct 2026 18:44 UTC; tree identical to `0d124d2` | VERIFIED (`git fetch`, `rev-parse ^{tree}`) |
| R4 commits | `2df9670`, `70665a8`, `0d124d2` all in `main` | VERIFIED |
| CI on `main` `c46df2b` | run 40380695927 (`push`) success; PR run 40380439942 success | VERIFIED (`gh run list`) |
| PR #6 | merged by the team after the R4 report (the R4 report still says "not pushed"; superseded) | VERIFIED |
| Work tree at start | clean on `r4/final-prototype` = `origin/r4/final-prototype` | VERIFIED |
| New branch | `r45/final-freeze` from `origin/main`, **no upstream** (so a bare push cannot reach `main`). Commits: `431b18c` (fix + tests) and the documentation commit containing this file | VERIFIED |
| Pushed / PR / merged | no / no / no | HUMAN_APPROVAL_REQUIRED |
| Console on 127.0.0.1:37539 (R4 note) | no listener at R4.5 start; nothing to stop | VERIFIED (`ss -ltnp`) |

## 3. UI defect resolved: phone viewport shift (details: `R45_VISUAL_QA.md`)

- **Cause (demonstrated):** the header's first row was ~512 px of unwrapped text during an operator session and ran
  146–200 px past a 320–390 px screen. Under mobile emulation Chromium widened the layout viewport to the content, which
  hid the overflow from the `innerWidth`-based test helper; opening the evidence sheet then panned the visual viewport by
  the overflow, and hash navigation kept the pan.
- **Fix:** CSS only, below 700 px: two-line header. No clipping, no `overflow-x: hidden`.
- **Tests:** stricter `no_overflow` (`clientWidth`, `visualViewport.pageLeft == 0`) plus
  `test_phone_header_fits_and_the_page_does_not_shift[320|360|390]`. Old CSS: 5 failed, 10 passed. Fix: 15 passed.
- **Sweep:** 340 layout measurements over 18 widths (320–1440) and 75 interaction steps (zoom, pan, text view, sheet,
  verify, tamper, Escape, long run ID, history, reload): 0 overflow, 0 pan, 0 page errors.
- R4-UI-1/2/3 still fixed (their tests pass).

## 4. Working prototype (recorded live run, clean clone of `431b18c`)

| # | Step | Observed | Status |
|---|---|---|---|
| 1 | Start console | `start_prototype.sh --reset`: `Mode: LIVE`, Podman 5.8.9 rootless, image rebuilt (cache hit `f0825fec…`) | VERIFIED |
| 2 | Single-use link | Read-only → `Operator session · roles act server-side` | VERIFIED |
| 3–6 | Create, defence, freeze, start | Hardened defence, padding 0 ms; CREATED 07:54:50 IST, FROZEN 07:54:52, RUNNING 07:54:54 | VERIFIED |
| 7–8 | Real execution, SEALED | 07:54:56, `10 of 10 evaluated`, 25 entries signed | VERIFIED |
| 9–10 | Prohibited operations | PASS: red read 403, red release 403, anonymous read 403; still SEALED; 0 of 18 protected markers | VERIFIED |
| 11 | Signed audit entries | `policy.denied` #26, #27, #28 signed; Decision = denied shows 8 of 29 (also #9–#13 broker denials during the run) | VERIFIED |
| 12 | Authorised release | HTTP 200, #29 `run.released`, RELEASED, `blocked_input 8 · safe_output 2` | VERIFIED |
| 13 | Verify authentic | console: accepted, exit 0; CLI with pinned key and recorded terminal hash `sha256:7b5031aa…026e`: exit 0, 29 entries, 7 checkpoints | VERIFIED |
| 14–15 | Tamper a disposable copy | console: copy exit 1 rejected, original exit 0, byte-identical, copy deleted; CLI: exit 1, seq 11 "entry content does not match its hash"; original `sha256sum -c` OK | VERIFIED |
| 16 | End session | back to Read-only | VERIFIED |
| 17 | Stop and clean up | SIGINT to the launcher: exit 0, port 8400 closed, 0 `aegis-lab-*` containers | VERIFIED |

Run ID: `LAB-001` (27 Oct 2026, 02:24–02:26 UTC). A first recording attempt stopped on a recorder race after LAB-001
reached RELEASED; it was discarded and the console restarted with `--reset` (section 5). These results are for this run
on this host only.

## 5. Final corrected demo video (details: `R45_MEDIA_PROVENANCE.md`)

| Item | Value |
|---|---|
| File (team workspace) | `round2/final_submission/video/AegisLab_R45_Final_Prototype.mp4` |
| SHA-256 | `9ac645b2afe342e3f8bcf840e7642b9506ebd3787c554f30d23291d040bea855` |
| Captions | `AegisLab_R45_Final_Prototype.srt`, 47 cues, SHA-256 `0c243b50…a029` |
| Length, format | 140.99 s (2:21), 1920x1080, 30 fps, H.264 High, AAC 48 kHz stereo |
| Source revision | `431b18c0b51b674d92a865937f88d2faf5aaf7f1`, clean clone |
| Labels | **RECORDED EXECUTION — LIVE SANDBOX / STUB MODEL** on console footage; **PRECOMPUTED REAL-MODEL EVIDENCE** on Experiments |
| Beats | intro 0:00, architecture 0:13, session 0:30, lifecycle 0:39, sealed 0:50, denied 0:57, permitted release 1:11, audit 1:19, verify 1:26, tamper 1:33, precomputed 1:41, limits 1:54, end card 2:13 |
| Media checks | 4,214/4,214 frames decoded, 0 errors; 0 clipped samples; 0.0 s speech outside cues; 0 cues without speech |
| Secret checks | 12 DOM/text checks, 0 hits; kept files 0 hits; OCR NOT_RUN |
| Human sign-off | HUMAN_APPROVAL_REQUIRED |

The R4 video (`round2/final_prototype/`, graph-caption overlap) is unchanged and is no longer the recommended upload.

## 6. Public artifact safety

- `round2/final_submission/` is built from an allowlist: video, captions, transcript, technical description, judge
  instructions, repository/revision note, media provenance, human checklist, `SHA256SUMS`. It contains **no** raw frames,
  evidence bundle, launcher log, browser trace, key, token or local path (scanned, section 7).
- The raw recording (1,322 frames), the LAB-001 evidence bundle (public key only) and all logs stay in the private
  workspace `round2/final_r45/`.
- Repository changes: one CSS block, two test files, four documents, 31 screenshots of the gate run in
  `docs/prototype/screenshots/r45/` (same kind as the r3/r4 sets). No video, cookie, launch code, key or token tracked.

## 7. Test and regression results

| # | Gate | Working tree `431b18c` | Clean clone `431b18c` |
|---|---|---|---|
| 1 | `release_gates.sh --with-browser --strict` | 8 PASS, 0 failed, 0 skipped | 8 PASS, 0 failed, 0 skipped |
| 2 | Full pytest (`.venv`) | 463 passed, 2 skipped | 463 passed, 2 skipped |
| 3 | Rootless Podman tests | 13 passed | 13 passed |
| 4 | Browser core | 15 PASS | 15 PASS |
| 5 | Browser live | 3 PASS | 3 PASS |
| 6 | Judge demo | 17/17 | 17/17 |
| 7 | Security demo | 34/34 + 1 documented limit (not a pass) | 34/34 + 1 limit |
| 8 | Claims checker | PASS (14/14 numbers) | PASS |
| 9 | Publication scan (git index) | 0 FAIL 0 WARN | 0 FAIL 0 WARN |
| 10 | `MANIFEST.sha256` | 259 OK | 259 OK |
| 11 | Signed evidence (recorded run) | — | exit 0 (section 4) |
| 12 | Tamper rejection | — | exit 1, original unchanged |
| 13 | Responsive inspection | 340 + 75 checks, 0 failures | — |
| 14 | Media integrity | section 5 | — |

The 2 skips are the browser modules under `.venv` (no Playwright there); they run in rows 4–5 through `.venv-browser`.
Skipped: none else. Not run: OCR of frames; hosted CI for this branch (not pushed); real-model experiments (unrelated
to a CSS change; their saved results are unchanged and pass the claims checker).

Historical integrity: `aegislab/evidence/` and `MANIFEST.sha256` unchanged since `c46df2b`; r3_rc1 candidate 56 OK;
R0.6 package 13 OK; R4 workspace 1,309 OK; tag `aegislab-r3-rc1` → `9516944` locally and on GitHub. The r3 screenshot set
regenerated by the browser tests was restored after every run.

## 8. GitHub PR / CI / merge

Not pushed. Prepared: branch without upstream; PR body draft in the workspace (`round2/final_r45/PR_BODY.md`), title
*Phase R4.5: phone header fix, final video provenance and release records*. After an approved push: check the remote SHA,
open the PR, read every gate of the `release-gates` run, merge only after separate approval, then validate the merged
`main` from a clean clone and confirm `git diff --stat 431b18c <main> -- aegislab/` is empty (release-video consistency).

## 9. Submission status

Deadline 28 October 2026 (IST), through the organizers (team statement). Organizer instructions are not in the
workspace: HUMAN_CONFIRMATION_REQUIRED. Ready: repository URL, video (pending sign-off), technical description, judge
walkthrough. **Not submitted.** Checklist: `R45_RELEASE_CHECKLIST.md`.

## 10. Files changed in R4.5 (branch `r45/final-freeze`)

| Commit | Files |
|---|---|
| `431b18c` | `aegislab/web/console/console.css` (+8 lines, `max-width: 699px` block), `aegislab/tests/browser/conftest.py`, `aegislab/tests/browser/test_console_browser_core.py` |
| documentation commit | `docs/release/PHASE_R45_FINAL_REPORT.md`, `R45_RELEASE_CHECKLIST.md`, `R45_MEDIA_PROVENANCE.md`, `R45_VISUAL_QA.md`; `docs/prototype/screenshots/r45/` (31 PNG) |
