# R4.5 media provenance: final prototype video

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · 27 October 2026 (IST).

The video is **not** in this repository (media is never committed). It lives in the team workspace: the public upload
package `round2/final_submission/` and the private validation workspace `round2/final_r45/` (raw frames, evidence bundle
of the recorded run, logs). This file records how it was made so that the claim "it shows commit X" can be checked.

**Status: AUTOMATED CHECKS PASSED · HUMAN WATCH-AND-LISTEN SIGN-OFF REQUIRED.**

## Files

| File | SHA-256 | Properties |
|---|---|---|
| `AegisLab_R45_Final_Prototype.mp4` | `9ac645b2afe342e3f8bcf840e7642b9506ebd3787c554f30d23291d040bea855` | 140.99 s container (140.5 s render), 1920x1080, 30 fps, H.264 High yuv420p, AAC 48 kHz stereo, captions burned in |
| `AegisLab_R45_Final_Prototype.srt` | `0c243b50b959e0db12192f418c68c2e237bd1a1d90d00a322d2bba319dd2a029` | 47 cues, the burned-in caption text |

## Source revision

- **Code shown:** `431b18c0b51b674d92a865937f88d2faf5aaf7f1` (branch `r45/final-freeze`), from a fresh `git clone --no-local`,
  `git status` clean. It is public `main` `c46df2b` plus the R4.5 CSS/test commit only.
- Backend, sandbox and Containerfile identical to `c46df2b` and `7434152`; sandbox image `f0825fec8c3b…` (unchanged).
- The recording viewport (1280x720) is above the 700 px breakpoint of the only R4.5 code change, so the frames would be
  identical on `c46df2b`; the R4 fixes (graph caption below the drawing, lifecycle gap) are visible.
- Any later commit on this branch is documentation only. If the branch merges with code changes, the video must be
  re-checked against them (see `R45_RELEASE_CHECKLIST.md`).

## Execution-mode labelling

- Console footage carries the band **RECORDED EXECUTION — LIVE SANDBOX / STUB MODEL** (green), with
  `recorded 27 Oct 2026 · commit 431b18c`.
- The Experiments page carries **PRECOMPUTED REAL-MODEL EVIDENCE · SAVED QWEN2.5-0.5B RUNS · NOT RERUN** (purple).
- Title card: "Recorded walkthrough: the browser actions and backend results are real." The narration says "a
  recording of a real run" and "the model is a deterministic stub, not an LLM".

## How it was recorded

| Step | Detail |
|---|---|
| Console | `scripts/start_prototype.sh --check`, then `--reset`: `Mode: LIVE`, Podman 5.8.9 rootless, Python 3.14.8, stub model, loopback only |
| Browser | fresh headless Chromium context (Playwright 1.64.1), 1280x720 at scale 1.5, page viewport only (no address bar) |
| Capture | Chrome DevTools screencast, 1,322 frames with browser timestamps, 120.2 s, started 27 Oct 2026 02:24:22 UTC (07:54 IST) |
| Interaction | real mouse moves and clicks; every wait is on a real backend state (CREATED, FROZEN, RUNNING, SEALED, PASS verdicts, RELEASED, exit codes) |
| Additions | drawn mouse pointer (headless screencasts show none), title and end cards, label band, captions, Piper voice `en_US-lessac-medium` (SHA-256 `5efe09e6…f019f`, same as R0.5–R4) |
| Not done | no speed change, no reordering, no edits to page content, no fabricated terminal or output |
| Run IDs | `LAB-001` only; 0 page errors |
| First attempt | stopped by a recorder race (`Element is not attached to the DOM`, a live table re-rendered during a scroll) after LAB-001 reached RELEASED; footage deleted unused; console restarted with `--reset`; recorder now retries that scroll |

## What the recorded run showed (LAB-001)

Hardened defence, padding 0 ms. CREATED 07:54:50 → FROZEN 07:54:52 → RUNNING 07:54:54 → SEALED 07:54:56, 10 of 10
attacks evaluated. Prohibited access: red read, red release and anonymous read each **403**, signed `policy.denied` #26,
#27, #28, run still SEALED, 0 of 18 protected markers in responses. Reviewer release: HTTP 200, #29 `run.released`,
outcomes `blocked_input 8 · safe_output 2`. Audit (denied): 8 of 29 entries, all signed. Console verification: accepted,
exit 0. Console tamper (entry 11): copy exit 1 rejected, original exit 0, byte-identical, copy deleted. End session:
Read-only.

## Independent verification after shutdown

| Check | Result |
|---|---|
| `python -m aegis.verify_cli` on the exported LAB-001 bundle, key pinned out of band, `--expect-state RELEASED`, `--expect-terminal-hash sha256:7b5031aa…026e` (the reviewer's recorded value), retained anchor | exit 0, `ok: true`, 29 entries, 7 checkpoints, terminal verified, key `sha256:0ad835b17c45d79b` |
| Same on a disposable copy with `data.tampered=true` in entry 11 | exit 1, `chain_ok: false`, seq 11 "entry content does not match its hash" |
| Original bundle after both | `sha256sum -c` OK |

## Media checks

| Check | Result | Status |
|---|---|---|
| Full decode | 4,214 / 4,214 frames, 0 errors | VERIFIED |
| Audio | peak 0.80, RMS −19.2 dBFS, 0 clipped samples | VERIFIED |
| Captions vs speech | 101.2 s speech, 0.0 s outside cues, 0 cues without speech | VERIFIED |
| Narration vs events | each beat starts at the recorded start of its action; stills at 13 times compared with captions | VERIFIED (by Claude) |
| Stills | 13 stills: text legible, correct bands, no graph overlap, no clipped lifecycle, no overflowing button | VERIFIED (by Claude, not a person) |
| Secret exposure (DOM/text, every beat and after logout) | 12 checks against launch code, CSRF token, session cookie, key and role-token strings, canaries, local paths: 0 hits | VERIFIED |
| OCR of frames | no OCR tool on the host | NOT_RUN |
| Human watch-and-listen | — | HUMAN_APPROVAL_REQUIRED |
