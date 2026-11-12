# AegisLab

**Secure infrastructure for adversarial AI safety testing** · Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora) · Grand Finale, Manali

## What it is

A single-host lab where a red team, a blue team and the model under test run side by side without seeing each other's protected state. Each workload runs in a rootless Podman container with no network and its own user namespace; one trusted broker is the only channel; the real model (llama.cpp on CPU) runs in its own sandbox behind a UNIX socket. Every decision lands in a hash-chained, signed audit log that a reviewer verifies offline with a separate program.

## Three headline results

- **No cross-session leak detected with a real model, and the controls show the test can see one.** Qwen2.5-0.5B: 0 of 104 sessions (0 of 1040 isolation trials) recovered another session's canary; controls built to leak: 16 of 16 sessions and 13 of 16 sessions. RE-MEASURED 11 Nov 2026.
- **A timing leak we found ourselves, and fixed.** 250 ms response padding leaked against the real model (accuracy 0.945/0.960/0.950, RE-MEASURED 11 Nov 2026); deadline release: accuracy 0.495/0.545/0.575 against baselines 0.515/0.540/0.515, no leak detected (RE-MEASURED 11 Nov 2026), at +519 to +621 ms per answer (RE-MEASURED 11 Nov 2026).
- **Evidence that cannot be edited unnoticed.** 19/19 tamper categories detected in 30/30 trials (RE-MEASURED 11 Nov 2026); strict verification exit code 0, a one-field edit of a copy exit code 1 (LIVE).

Labels: LIVE = produced by the presented code when it runs · RE-MEASURED = measured again on the finale code · RECORDED = measured earlier, not re-run.

## Residual risk, stated

A host-user compromise still reaches the signing key (the reviewer countersignature is Partial: it helps only off-host); "no leak detected" is not absence; containers share the kernel (gVisor not tried); one host, CPU only, GPU untested; the canary detector misses double encodings and paraphrase.

## Try it

- Code and evidence: **https://github.com/Invinciblx777/HIH**
- Read-only public demo (verify a real bundle, watch a tampered copy fail): **https://aegislab-demo.onrender.com**. It runs on Render and serves `main`, where the finale code is merged.
- `cd aegislab && bash scripts/quickstart.sh && bash scripts/judge_demo.sh`

Abdul Munaf Z (solution architect & integration engineer) · Likhith Sai N (sandbox security & infrastructure engineer) · Sreeram Rajesh (product interface & evaluation engineer)
