# R4.5 release checklist

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · deadline **28 October 2026, IST** (from the team).
Submission is through the organizers, not Unstop. The organizer's own instructions are not in the workspace:
channel, form, required links and video rules are **HUMAN_CONFIRMATION_REQUIRED**.

Legend: `[x]` done and verified by a command · `[ ]` open · **(human)** needs a person.

## A. Engineering (done in R4.5)

- [x] Baseline: PR #6 merged; `origin/main` = `c46df2b`, tree identical to `0d124d2`; push CI run 40380695927 green.
- [x] Phone viewport shift: root cause demonstrated, CSS fix `431b18c`, regression test fails before (5 failed) and passes
      after (15 passed). Details: `R45_VISUAL_QA.md`.
- [x] R4-UI-1/2/3 still fixed (tests pass).
- [x] Gates on the working tree and on a clean clone of `431b18c`: see `PHASE_R45_FINAL_REPORT.md` section 7.
- [x] Real live run recorded from the clean clone; denials, release, verification and tamper rejection observed;
      independent CLI verification exit 0 / tampered exit 1.
- [x] Final video rendered and machine-validated; hashes in `R45_MEDIA_PROVENANCE.md`.
- [x] Public package `round2/final_submission/` built from an allowlist with `SHA256SUMS`; no raw frames, no evidence
      bundle, no launcher log, no private paths (scanned).
- [x] Historical records unchanged: `MANIFEST.sha256` 259 OK, `aegislab/evidence/` untouched, r3_rc1 56 OK, R0.6 13 OK,
      R4 workspace 1,309 OK, tag `aegislab-r3-rc1` → `9516944` locally and on GitHub.
- [x] Stray console on 127.0.0.1:37539 from an earlier session: no longer running (no listener at R4.5 start).

## B. Publication (needs approval; nothing below has been done)

- [ ] **(human approval)** Push `r45/final-freeze` to `origin` (it has no upstream set on purpose, so a bare `git push`
      cannot reach `main`): `git push -u origin r45/final-freeze`.
- [ ] Open PR *Phase R4.5: phone header fix, final video provenance and release records* into `main`
      (draft body: `round2/final_r45/PR_BODY.md` in the workspace).
- [ ] Wait for the `release-gates` workflow on the PR; read every gate in the job log; diagnose any failure, never bypass.
- [ ] **(human approval)** Merge.
- [ ] After merge: clean `git clone` of the new `main`; run `scripts/release_gates.sh --with-browser --strict`,
      `pytest -m podman`, `judge_demo.sh`, `security_demo.sh`, `run_browser_tests.sh --all --require`.
- [ ] Release-video consistency: `git diff --stat 431b18c <merged main> -- aegislab/` must be empty (docs only). If any
      code, CSS or JS differs, re-check the affected footage and re-record if it changes what is shown.

## C. Submission (human)

- [ ] **(human)** Read the organizer's submission instructions; confirm deadline time, channel, required items, video
      length and format rules.
- [ ] **(human)** Watch and listen to `round2/final_submission/video/AegisLab_R45_Final_Prototype.mp4` end to end, with
      sound; tick `round2/final_submission/HUMAN_CHECKLIST.md`.
- [ ] **(human)** Upload the video where the organizers require; check the link while logged out.
- [ ] **(human)** Submit the repository URL, video link and technical description; save the confirmation.
- [ ] **(human)** Social posts only if the organizers require them; nothing has been posted.
- [ ] Record the real submission confirmation. Until then the project is **not submitted**.
