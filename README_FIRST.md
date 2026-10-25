# Tech Mavericks · AegisLab · Hack in Hills ’26 submission (Phase 4 candidate)

**Track 04: Securing Adversarial AI Safety Testing Infrastructure (Bayora).**
AegisLab is controlled, measurable, adversarial AI testing infrastructure: red-team attacks, blue-team defences and the model under test coexist without leaking protected state, and every run ships evidence a reviewer can verify independently.

Team: Abdul Munaf Z (solution architect & integration engineer) · Likhith Sai N (sandbox security & infrastructure engineer) · Sreeram Rajesh (product interface & evaluation engineer).

This folder is a **candidate**, not promoted. Earlier candidates (`release_2026-10-22`, Phase 1, 2 and 3 candidates), `submission/` and `_baseline/` are unchanged and sit beside it.

## Package contents

| # | Deliverable | File |
|---|---|---|
| 1 | Editable 8-slide deck on the official template, speaker notes on every slide | `Tech_Mavericks_AegisLab_Submission.pptx` |
| 2 | Matching PDF (8 pages), exported from that PPTX | `Tech_Mavericks_AegisLab_Submission.pdf` |
| 3 | Pitch video, 120.000 s, 1920x1080, 30 fps, H.264 + AAC | `Tech_Mavericks_AegisLab_Pitch_120s.mp4` |
| 4 | Voice-over script, storyboard, captions (burned in and as SRT) | `Voiceover_Script.txt`, `Storyboard_Timestamped.txt`, `Captions.srt` |
| 5 | Claim-to-evidence matrix | `PHASE4_CLAIM_MATRIX.md` (source: `PHASE4_CLAIM_MATRIX.json`) |
| 6 | Judge Q&A | `Judge_QA.md` |
| 7 | Phase 4 report: validation, media notes, recommendation | `PHASE4_PRESENTATION_REPORT.md` |
| 8 | Prototype, evidence and tests | `aegislab/` (start with `aegislab/README.md`, `aegislab/THREAT_MODEL.md`) |
| 9 | Deck and video build sources | `presentation_src/` |
| — | Earlier reports | `PHASE2_SECURITY_REPORT.md`, `PHASE3_LLM_SECURITY_REPORT.md`, `VALIDATION_ADDENDUM_2026-10-22.md`, `RELEASE_READINESS_REPORT.md`, `PROTOTYPE_REPORT.md` (historical; figures in them are those of their date) |
| — | Hosted website URL | **Not deployed.** No public URL exists. |

## Live demonstration (judge-ready path) and fallback

Presentation mode is explicit and separate from the original demo. It is deterministic, local and offline: no model download, no internet, no GPU.

```bash
cd aegislab
bash scripts/quickstart.sh            # once: venv, dependencies, sandbox image, full test suite, DEMO-001, strict verification
bash scripts/judge_demo.sh            # PRESENTATION MODE: runs in seconds; add --pause to step with Enter, --record F.json for a timestamped transcript
bash scripts/security_demo.sh         # the original, longer demonstration (unchanged)
```

`judge_demo.sh` steps: 1 threat model; 2 a legitimate evaluation (stub model, run JD-1); 3 blocked unauthorized operations, including a hostile mailbox attack from a real rootless container; 4 strict verification of the completed bundle with key and terminal hash pinned; 5 a tampered copy is rejected; 6 LLM isolation evidence, **PRECOMPUTED** from the saved real-model runs (the demo does not run a model and never claims to; each line names its run ID and raw artifact); 7 residual risks. Result of the recorded execution: 17 / 17 checks.

**Fallback if the live run fails:** `aegislab/evidence/phase4_2026-10-23/judge_demo_transcript.txt` is the output of a real successful execution (JSON with per-line time offsets beside it). The deck and video show excerpts of that same recording. Present it as a recording, not as a live run.

## Verify the numbers

```bash
cd aegislab
python evaluation/check_claims.py              # recomputes quoted figures from raw files (14 / 14, 72 / 72, 48 / 48: 134 / 134 checks; `--full` runs 84 timing checks)
python evaluation/check_claims.py --full       # also recomputes the timing permutation tests (about 7 minutes)
python evaluation/check_presentation.py        # deck, notes, voice-over, captions, storyboard, README, Q&A against the matrix and the raw evidence
python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released --run-id DEMO-001 --expect-state RELEASED   # strict, exit 0
```

Validation of this release (one host, Fedora, rootless Podman 5.8.9): 345 tests passed; quickstart 8 / 8; security demo 34 / 34 plus one documented limit; judge demo 17 / 17; presentation and claims checkers pass. Commands, exit codes and anything skipped: `PHASE4_PRESENTATION_REPORT.md`.

## What the deck and video claim, and what they do not

- **Measured, current:** boundary enforcement (role matrix 560 attempts, 419 / 419 expected denials denied), the hostile-mailbox attack blocked, strict verification and tamper rejection, broker hop 2.59–2.84 ms median, timing padding at 250 ms accuracy 0.495–0.555 versus 0.795–0.800 unpadded at +198 to +201 ms per answered request (lowers one classifier's accuracy; does not show the channel is gone).
- **Precomputed, real model:** Qwen2.5-0.5B Q4_K_M on CPU llama.cpp, loopback only: 0 / 104 sessions leaked, controls that must leak did (16 / 16, 13 / 16), pipeline 0 / 26 runs, prompt-cache oracle with the cache on, injection and failure handling. One model, ten probe wordings; GPU memory, accelerator KV cache and hardware side channels were **not tested**; zero observed leaks do not prove zero risk.
- **Historical, labelled as such:** the Phase 1 broker's audit-log overwrite (recorded before the fix, not re-run).
- **Not claimed:** invulnerability, GPU or physical KV-cache isolation, model robustness to prompt injection, protection against a compromised broker or signing key, any deployment, customer, partner or certification. The canary detector does not recognise every re-encoding (for example base64).

## Video production notes

Slides are renders of the submitted PDF; the demo frames are the recorded terminal text of `judge_demo.sh`. Narration: Piper `en_US-lessac-medium`, synthesised locally (check the voice's own licence before reuse). Captions are split inside each sentence in proportion to character count, so their timing inside a sentence is approximate. No playback speed change anywhere. Rebuild: `presentation_src/` (needs `python-pptx`, Pillow, numpy, `piper-tts`, `imageio-ffmpeg`, LibreOffice and the fonts in `aegislab/web/fonts/`).

## Fonts and imagery

The deck keeps the template's Montserrat and IBM Plex Sans (and Caveat on the closing slide). The mountain photograph and event logos come from the official template and are used only as the template uses them. `presentation_src/official_template.pptx` is the template the deck was built on.
