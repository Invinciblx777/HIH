# Finale package (Grand Finale, Manali)

Everything here is generated from `claims_used_for_finale.json`, which `aegislab/evaluation/check_finale_presentation.py --write-claims` derives from `aegislab/evaluation/check_claims.py` (all parts must pass), the finale evidence files, the recorded terminal transcripts in `terminal/` and the gate counts in `evidence/p5_gate_counts.txt`. No figure is typed by hand. Each claim carries its type: LIVE, RE-MEASURED <date> or RECORDED <date>.

Presented code: branch `finale/p4-hardening`, commit `9145592`, plus this package (branch `finale/p5-media`). P1–P4 are not merged into `main` yet.

| File | What |
|---|---|
| `Tech_Mavericks_AegisLab_Finale.pptx`, `.pdf` | the 12-slide deck on the official template, speaker notes on every slide |
| `FINALE_SCRIPT.md` | 3-minute, 6-minute and 10-minute talk tracks, slide and demo cues, a fallback line per live step |
| `FINALE_JUDGE_QA.md` | judge Q&A with evidence paths |
| `HANDOUT.md`, `AegisLab_Finale_Handout.pdf` | one-page handout |
| `captions/*.srt` | captions of the judge cut and the walkthrough (the videos themselves are outside the repository, see below) |
| `terminal/t*.txt` | the recorded terminal sessions (ANSI removed) used on the slides and in the videos |
| `evidence/p5_gate_counts.txt` | test and gate counts quoted by the package |
| `src/` | every generator: recorder, screenshot driver, deck builder, doc templates, narration, video renderer, OCR scan |

## Rebuild

```
cd aegislab && .venv/bin/python evaluation/check_finale_presentation.py --write-claims && cd ..
MEDIA_PY=<python with python-pptx, pillow> bash finale_package/src/build_all.sh <media dir with screens/, term/>
aegislab/.venv/bin/python aegislab/evaluation/check_finale_presentation.py
```

The videos (`AegisLab_Finale_Judge_Cut.mp4`, `AegisLab_Finale_Walkthrough.mp4`), the raw terminal recordings, the screenshots and the rendered keyframes are kept outside the repository with a `SHA256SUMS` file (they are binary media, not source). `src/render_video.py` rebuilds the videos from them. The narration is a synthetic voice (Piper) and must be listened to by a person before use.
