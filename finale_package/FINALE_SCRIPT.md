# AegisLab · Grand Finale talk tracks (3-minute, 6-minute and 10-minute)

Team Tech Mavericks · Hack in Hills '26 · Track 04 · Grand Finale, Manali, 20–21 Nov 2026.

- **Code presented:** branch `finale/p4-hardening`, commit `9145592`. P1–P4 are **not merged into `origin/main`**; the hosted read-only demo serves `main` until they are.
- **Figures:** every figure below comes from `finale_package/claims_used_for_finale.json` and carries its type: **LIVE** (the presented code produces it when it runs; the number is the one from the rehearsal on 12 Nov, and the stage run must reproduce it), **RE-MEASURED <date>** (measured again on the finale code) or **RECORDED <date>** (measured earlier, not re-run). `aegislab/evaluation/check_finale_presentation.py` fails if a figure here differs from that file or lacks its label.
- **Format:** no file in `docs/round2/` or `round2/` records the finale format (`docs/round2/REQUIREMENTS_LOG.md` gives only the dates and the venue). The main track assumes a 6-minute pitch with a live demo, then judge Q&A. The 3-minute and 10-minute tracks reuse the same slides.
- **Never show:** the console launch link, API keys, `/home/...` paths, browser profile names. The launch link is opened off-screen before the talk.

Cue legend: **[SLIDE n]** change slide · **[DEMO]** switch to the terminal or browser · **[FALLBACK]** what to say and show if the live step fails · *(stage note, not spoken)*.

## Before going on stage (offline, about 10 minutes before)

1. `cd HIH/aegislab && bash scripts/real_model_demo.sh`: must end with 13/13 checks (LIVE). If not, use the fallbacks below for every real-model step.
2. In a second terminal: `bash scripts/start_real_model_console.sh`. Open the printed link in the browser **with the projector off or the window hidden**, then close the terminal tab that shows it. The browser lands on the Lab page with the header "REAL MODEL · LIVE".
3. Open the walkthrough video `AegisLab_Finale_Walkthrough.mp4` and the judge cut `AegisLab_Finale_Judge_Cut.mp4` in a player, paused at 0:00, on the same laptop (no network needed).
4. Clear the terminal (`clear`), set a large font, and hide the shell history.
5. Phone: open https://aegislab.vercel.app if the venue has network; otherwise skip that step.

## 6-minute track (main)

| Time | Cue | Spoken (approximate; keep the figures and their labels exact) |
|---|---|---|
| 0:00–0:25 | **[SLIDE 1]** | "We are Tech Mavericks, and this is AegisLab. In an AI safety test a red team attacks, a blue team defends and the model answers, on one system. If red can read the defence, or one session can read another's data through the model, or a result is edited afterwards, the score measures the leak, not the model. Isolation decides whether the evaluation is valid." |
| 0:25–0:50 | **[SLIDE 2]** | "Six flows are forbidden, and each one is attacked in a test. The role matrix alone made 560 attempts with 419/419 denied (RE-MEASURED 11 Nov 2026)." |
| 0:50–1:25 | **[SLIDE 3]** | "Five layers: rootless containers with no network, one trusted broker, a role gate, stateless model calls, and a signed audit chain. The real model runs in its own container with no network, reached through a UNIX socket. New for the finale: every container runs as container UID 900 on its own host UID, never as the broker's UID 1000; a mounted key gives errno 13 (RE-MEASURED 11 Nov 2026)." |
| 1:25–1:35 | **[SLIDE 4]** | "Here is what you will see live, and what is recorded if the venue fails us." |
| 1:35–2:10 | **[DEMO]** terminal | Type `bash scripts/real_model_demo.sh`. While it runs: "This is the real model, now: stateless sessions, a control that must leak, and a leak the model makes through a broken gateway, withheld by our broker, even in base64." When it ends: "13/13 checks in about 28 s (LIVE)." |
| 2:10–2:50 | **[DEMO]** browser, Lab | Create run (default policy) → Freeze → Start. "Default policy with the real model: deadline release." When it seals, point at the run card: "REAL MODEL · LIVE, deadline release at t0 + 1400 ms (LIVE)." Run the authorised-release scenario. |
| 2:50–3:20 | **[DEMO]** browser, Evidence | Verify LAB-001: "Accepted by the independent verifier." Tamper with a copy: "One edited entry: rejected, original byte-identical." |
| 3:20–3:50 | **[SLIDE 5]** | "Real model, re-measured on the finale code: 0 of 104 sessions and 0 of 1040 isolation trials leaked (RE-MEASURED 11 Nov 2026), while the controls built to leak did: 16 of 16 sessions and 13 of 16 sessions (RE-MEASURED 11 Nov 2026). No leak detected is not no leak: the upper bound is 2.84% of sessions (RE-MEASURED 11 Nov 2026)." |
| 3:50–4:35 | **[SLIDE 6]** | "The result that changed. With the stub, 250 ms padding works: 0.435–0.540 at 250 ms (RE-MEASURED 11 Nov 2026). Against the real model it broke: 1.000 at 250 ms (RECORDED 10 Nov 2026). Our own test found that. Deadline release fixed it: accuracy 0.495/0.545/0.575 against baselines 0.515/0.540/0.515 (RE-MEASURED 11 Nov 2026). The third execution's p = 0.044 is below 0.05 but above our pre-declared 0.05/9 = 0.0056 (RE-MEASURED 11 Nov 2026), so we say 'no leak detected', not 'no leak'. It costs +519 to +621 ms per answer (RE-MEASURED 11 Nov 2026)." |
| 4:35–4:55 | **[SLIDE 7]** | "Every decision is chained and signed, the terminal checkpoint makes truncation visible, and the reviewer countersigns. A broker-key forgery is refused, but a forger with both keys still wins, so the countersignature is Partial." |
| 4:55–5:10 | **[SLIDE 8]** | "For the finale we closed what you would press on: user namespaces, re-encoded canaries, 6 detectors (LIVE), capability tokens and quotas." |
| 5:10–5:20 | **[SLIDE 9]** | "One laptop, rootless, CPU only, offline. The public demo is read-only on purpose." |
| 5:20–5:45 | **[SLIDE 10]** | Read the two highlighted risks: host compromise reaches the key; no leak detected is not absence. "The rest is on the slide." |
| 5:45–6:00 | **[SLIDE 12]** | "Isolate, measure, prove. The code and every number are on GitHub. Thank you." *(Slide 11 is skipped; it is in the deck for questions.)* |

## 3-minute track

| Time | Cue | Spoken |
|---|---|---|
| 0:00–0:20 | **[SLIDE 1]** | Problem and why isolation decides validity (shortened from the 6-minute track). |
| 0:20–0:40 | **[SLIDE 3]** | "Rootless containers with no network, one trusted broker, a signed audit chain; the real model in its own container; every container on its own host UID (RE-MEASURED 11 Nov 2026)." |
| 0:40–1:20 | **[DEMO]** terminal | `bash scripts/real_model_demo.sh`: "13/13 checks (LIVE): a leak the model makes is withheld, the bundle verifies, a tampered copy is rejected." |
| 1:20–1:45 | **[SLIDE 5]** | "0 of 104 sessions leaked (RE-MEASURED 11 Nov 2026); the controls that must leak did." |
| 1:45–2:25 | **[SLIDE 6]** | "250 ms padding broke against the real model, 1.000 at 250 ms (RECORDED 10 Nov 2026); deadline release: accuracy 0.495/0.545/0.575 (RE-MEASURED 11 Nov 2026), at +519 to +621 ms (RE-MEASURED 11 Nov 2026)." |
| 2:25–2:50 | **[SLIDE 10]** | Host compromise and "no leak detected is not absence". |
| 2:50–3:00 | **[SLIDE 12]** | Close. *(Skip slide 2, slide 4, slide 7, slide 8, slide 9 and slide 11: type the slide number and Enter to jump.)* |

## 10-minute track

Same order as the 6-minute track, with these additions:

| Time | Cue | Added |
|---|---|---|
| 0:00–0:40 | **[SLIDE 1]** | The three verbs (isolate, measure, prove) and how to read the labels. |
| 0:40–1:30 | **[SLIDE 2]** | Walk F1–F6; F6 is the monitoring side channel closed in the finale work. |
| 1:30–2:30 | **[SLIDE 3]** | All five layers; the sandboxed model server; the F4 split: 4 containers, host UIDs 525188/526212/527236/528260 (RE-MEASURED 11 Nov 2026). |
| 2:30–2:45 | **[SLIDE 4]** | Demo plan. |
| 2:45–5:15 | **[DEMO]** | As in the 6-minute track, plus: the Audit page with the anomaly-detector panel open (the scripted red agent's probes fire two detectors); then in the terminal `.venv/bin/python evaluation/p4_userns_proof.py` with a scratch `AEGIS_VAR` and the table, 13/13 F4 checks (LIVE); then on the phone, the public demo's Verify button. |
| 5:15–5:55 | **[SLIDE 5]** | Add E2 to E5 and the second model: 0 of 280 isolation trials (RECORDED 10 Nov 2026). |
| 5:55–6:55 | **[SLIDE 6]** | Add the per-execution cost +519/+621/+529 ms and cut-offs 3–8 % (RE-MEASURED 11 Nov 2026), and why D is host-specific. |
| 6:55–7:35 | **[SLIDE 7]** | Add the tamper suite: 19/19 tamper categories, 40/40 tampered copies rejected (RE-MEASURED 11 Nov 2026). |
| 7:35–8:15 | **[SLIDE 8]** | Each hardening item and its limit. |
| 8:15–8:45 | **[SLIDE 9]** | Add CI and the checkers: check_claims 357/357 checks (LIVE). |
| 8:45–9:25 | **[SLIDE 10]** | All eight residual risks. |
| 9:25–9:45 | **[SLIDE 11]** | Future scope, each item tied to a risk. |
| 9:45–10:00 | **[SLIDE 12]** | Close. |

## Fallback lines (one per live step)

| Live step | If it fails, say | Then show |
|---|---|---|
| `real_model_demo.sh` does not reach 13/13 checks (LIVE) | "The model server is not cooperating on this machine. Nothing falls back to the stub, so here is the same script recorded on the same commit on 12 November." | Judge cut from 0:00, or the transcript `finale_package/terminal/t1_real_model_demo.txt` |
| The console does not start (Podman, port) | "Podman refused to start on the venue laptop. The walkthrough video is the same run on the same code." | Walkthrough video, the console section |
| The run does not seal in about a minute | "A slow model is cut off and red gets the uniform refusal; that is the deadline policy working. Let me show the sealed run we recorded." | Walkthrough video, run card |
| Verify does not say accepted | "A genuine bundle failing verification would itself be a finding; the recorded run shows exit code 0 and the tampered copy exit code 1 (LIVE)." | Slide 7, left terminal |
| F4 proof fails or takes too long | "Sampling the containers needs a quiet host; the recorded proof is on slide 3 and in the repository." | Slide 3, `finale_package/terminal/t4_f4_proof.txt` |
| Public demo unreachable or still shows the old verify bug | "The hosted demo serves main until our finale branches are merged; this laptop runs the same public mode." | Slide 9 screenshots |
| Projector or laptop fails | "We will talk you through the deck; the videos and the PDF are on a second device." | Handout PDF and the PDF deck on the backup device |

## Human checks before the finale

- Rehearse the 6-minute track twice with a timer; cut slide 8 to one sentence if over time.
- Practise the browser steps until the launch link is never on screen.
- Read slide 10 aloud once; it must not be skipped in any track.
