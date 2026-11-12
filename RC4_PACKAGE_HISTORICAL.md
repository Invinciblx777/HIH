# The rc4 package is historical

The presentation package at the repository root is the **rc4 submission of 23 Oct 2026**:

- `Tech_Mavericks_AegisLab_Submission.pptx` and `.pdf` (the 8-slide deck), `Tech_Mavericks_AegisLab_Pitch_120s.mp4`,
- `Captions.srt`, `Voiceover_Script.txt`, `Storyboard_Timestamped.txt`, `Judge_QA.md`, `README_FIRST.md`,
- `PHASE4_CLAIM_MATRIX.json` and `.md`, `PHASE4_PRESENTATION_REPORT.md`, `PHASE3_LLM_SECURITY_REPORT.md`, `presentation_src/`.

**Decision (finale P5, option a):** it stays exactly as submitted, labelled historical, and `aegislab/evaluation/check_presentation.py` keeps checking it against its own 23 Oct figures with **no expectation changed**. The only edits are one "HISTORICAL" line near the top of `README_FIRST.md`, `Judge_QA.md`, `Voiceover_Script.txt` (a bracketed line, which is not spoken or captioned), `Storyboard_Timestamped.txt`, `PHASE4_PRESENTATION_REPORT.md` and `PHASE3_LLM_SECURITY_REPORT.md`, and the same sentence appended to the note of `PHASE4_CLAIM_MATRIX.json` (its `.md` regenerated with `check_presentation.py --write-matrix-md`). `MANIFEST.sha256` was updated for exactly those files. The binaries and `Captions.srt` are unchanged.

**For the Grand Finale use [`finale_package/`](finale_package/)**: the deck, the 3-minute, 6-minute and 10-minute talk tracks, the judge Q&A, the handout and the captions, all generated from `finale_package/claims_used_for_finale.json` and checked by `aegislab/evaluation/check_finale_presentation.py`.

## What changed since rc4 (P3_REPORT section 5, items 1–17), and where each is now stated

| Item | Topic | Current statement | Where |
|---|---|---|---|
| 1, 14 | E2 context-sharing control | 2 of 4 runs, 17 attacks withheld (RE-MEASURED 11 Nov 2026) | `finale_package/FINALE_JUDGE_QA.md` question 2; deck slide 5 |
| 2, 14 | E3 cache-off latency AUC | AUC 0.41/0.56 (RE-MEASURED 11 Nov 2026) | `finale_package/FINALE_JUDGE_QA.md` question 2 |
| 3 | M3 latency medians | both the 23 Oct and the 10 Nov medians | `aegislab/THREAT_MODEL.md` row 4 (since finale P3) |
| 4, 10 | Timing with a real model | 250 ms buckets: accuracy 0.945/0.960/0.950, p = 0.001; deadline release: accuracy 0.495/0.545/0.575, p = 0.560/0.197/0.044 (RE-MEASURED 11 Nov 2026); cost +519 to +621 ms (RE-MEASURED 11 Nov 2026); real-model default D = 1400 ms (LIVE); every "padding brings it to chance" statement now says "stub model" | `finale_package/FINALE_JUDGE_QA.md` questions 3–5; `FINALE_SCRIPT.md`; README finale block; console Experiments page (`aegislab/web/console/console.js`, two strings fixed in P5) |
| 5 | A live real-model path exists | `scripts/real_model_demo.sh` 13/13 checks, console check 21/21 browser checks (LIVE) | `finale_package/FINALE_JUDGE_QA.md` question 14; README finale block |
| 6, 15 | check_claims totals | 357/357 checks, Part F 124/124 (LIVE); the security demo's "checks" count still names the Part E rows, which is what it counts | `finale_package/FINALE_JUDGE_QA.md` "Can I reproduce it?" |
| 7, 17 | Test counts | 702 tests passed, 18/18 browser tests (RECORDED 12 Nov 2026); MANIFEST entry count in `docs/finale/P5_REPORT.md` | `finale_package/FINALE_JUDGE_QA.md` "Can I reproduce it?"; `finale_package/evidence/p5_gate_counts.txt` |
| 8 | Second model | 0 of 280 isolation trials, controls 4 of 4 and 3 of 4 (RECORDED 10 Nov 2026) | `finale_package/FINALE_JUDGE_QA.md` question 9 |
| 9 | Re-run time of the real-model experiments | the measured wall clock of the 11 Nov run | `aegislab/evidence/finale_p4_2026-11-11/README.md`, "Command" line of `llm_final` |
| 11 | Canary detector and encodings | single encodings withheld; double encodings, ciphers, homoglyphs, paraphrase missed | `finale_package/FINALE_JUDGE_QA.md` question 8 |
| 12 | Key custody | containers on subordinate UIDs, errno 13 on the key (RE-MEASURED 11 Nov 2026); host-user compromise still reaches the key | `finale_package/FINALE_JUDGE_QA.md` question 6 |
| 13 | New controls | 6 detectors (LIVE), capability tokens, countersignature (Partial), quotas, digest pin | `finale_package/FINALE_JUDGE_QA.md` questions 6, 11, 12, "Can a tenant flood the broker?", "Is the deployment reproducible?" |
| 14 | E1 re-measured | 0 of 1040 isolation trials, 0 of 104 sessions; controls 16/16 and 13/16 (RE-MEASURED 11 Nov 2026) | `finale_package/FINALE_JUDGE_QA.md` questions 1–2 |
| 16 | Live demo counts | real-model demo 13/13 checks, console 21/21 browser checks, security demo 35/35 checks and 2 stated limits (LIVE) | `finale_package/FINALE_JUDGE_QA.md` questions 6, 14 and "Can I reproduce it?" |
