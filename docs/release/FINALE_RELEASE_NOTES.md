# AegisLab finale release notes

Team Tech Mavericks, Hack in Hills '26, Track 04. Grand Finale 20–21 Nov 2026, Manali.
Written 12 Nov 2026 (finale P6). Covers everything since the Round 2 submission (`0beba3d`, "UI refresh", 28 Oct 2026)
up to `main` at `105813b` (PR #15) and the P6 venue kit on the branch `finale/p6-kit`.

Figures here are the ones in the evidence folders and `finale_package/claims_used_for_finale.json`. Each one carries the
date it was measured. Nothing here is new evidence.

## 1. What changed since Round 2

| PR | Merged (UTC) | Merge | What |
|---|---|---|---|
| #9 | 12 Nov 01:44 | `1b88b04` | **P1, public demo and console fixes.** Verify on the public demo no longer fails with HTTP 403 (same-host Origin over https accepted). Read-only public mode is enforced in code: `AEGIS_PUBLIC_DEMO=1` is forced by `app.py`, session start and run creation are refused, and the Host guard is lifted only in that mode. |
| #10 | 12 Nov 01:44 | `a73f6bd` | **P2, fixes in hash-pinned files and a re-baseline.** Monitor side channel closed (514 hits before, 0 of 1,320 responses after). Quickstart command fixed. Tenant-storage race fixed (200/200 forced-pause runs). `cache_prompt: true` refused unless an explicit unsafe opt-in is set. A RELEASED run can no longer be recorded as FAILED. The access matrix, adversarial matrix, tamper suite and E1–E9 were re-measured on the new code; every figure was identical to 22/23 Oct. |
| #11 | 12 Nov 01:45 | `8b7fe99` | **P3, the real model live.** Qwen2.5-0.5B (Q4_K_M) on llama.cpp b11819, CPU, in rootless Podman with `--network none` and a UNIX socket. `real_model_demo.sh` and a real-model console. E1 isolation re-measured: 0 of 1,040 trials leaked, the same as 23 Oct. A second model, Qwen2.5-1.5B, in a reduced run: 0 of 280. The shipped 250 ms padding was found to leak the defence decision with a real model. |
| #12 | 12 Nov 01:45 | `8ba8b34` | **P4, hardening.** Deadline release (D = 1400 ms) is now the real-model default: no measured timing leak in three executions, at +519 to +621 ms per answered request and 3–8 % cut-offs. F4: every container runs as container UID 900 on its own subordinate host UID, never as the key owner (errno 13 on the key, 13/13 checks). Re-encoded foreign canaries (base64, hex, rot13, reversed, split, spelled out) are withheld. Six anomaly detectors write alerts into the signed chain. Base image pinned by digest. Capability tokens, reviewer countersignature, mailbox quotas. |
| #13 | 12 Nov 01:45 | `cb9af28` | **P5, presentation assets on the final code.** 12-slide deck with speaker notes, PDF, one-page handout, 3/6/10-minute talk tracks, judge Q&A, judge cut and walkthrough videos with captions. A new release gate, `check_finale_presentation.py`, checks every figure in them against the claims file. The Round 2 package (rc4) is kept as submitted and labelled historical. |
| #14 | 12 Nov 02:29 | `4266cb4` | **P6 task R, public read-only demo on Render.** `render.yaml` Blueprint (free plan) runs `app.py`, so the demo is always read-only. Per-client rate limit on the verifier and tamper (10 per minute; HTTP 429 with `Retry-After: 60`). The client is identified by the address Render's proxy adds; forged `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP` and `CF-Connecting-IP` headers do not reset the limit. `/api/lab/status` reports `public_demo`, `client_ip_header_present` and a `code_revision` hash of the served code. |
| #15 | 12 Nov 08:57 | `105813b` | **P6 R5, Render is the demo URL.** Every document, the deck, the handout and both videos now name https://aegislab-demo.onrender.com. The 429 message is shown as a readable toast in the console. The finale package was rebuilt (walkthrough segment w17 re-synthesised). |

### The hosted demo moved from Vercel to Render

- **New URL:** https://aegislab-demo.onrender.com, deployed from `main` by the Render Blueprint (`render.yaml`).
  Measured after the deploy of `105813b` (12 Nov): HTTP 200, `public_demo: true`, `client_ip_header_present: true`,
  and `code_revision` equal to the hash of the local checkout. The Render checks with Playwright passed 16/16 (desktop and phone).
- **Retired URL:** https://aegislab.vercel.app. It still serves the code of 28 Oct, where Verify fails with HTTP 403,
  because Vercel was not redeployed after the merge (polled for 11 minutes on 12 Nov). Every document marks it
  "outdated copy, do not use". Deleting or redeploying the Vercel project is up to its owner.
- **Repository homepage:** the GitHub "About" link now points to the Render URL instead of Vercel.
- **Free-plan cold start:** a Render free instance sleeps after about 15 minutes without traffic. The first request after
  sleep took **23.6 s** (12 Nov, after 16.5 minutes idle), then 0.22–0.24 s. A second attempt the same day, after 17
  minutes with no request from our machine, answered in 0.26 s: the instance had not slept, probably because of
  other traffic. Running `tools/venue/warm_render.sh` before the slot avoids the wait. Switching to a paid instance
  (`plan: 0.5c-512mb`) removes it; that change is prepared but not merged (it costs money; P6_REPORT section 8).

### P6 (branch `finale/p6-kit`, not merged)

- `tools/venue/`: `preflight.sh` (PASS/FAIL lines before the slot, optional Render checks), `reset.sh`, `warm_render.sh`,
  `offhost_reviewer.sh` (reviewer key kept on a removable device or a teammate's machine), `projector_check.py`.
- `tools/offline_kit/`: build, restore and offline proof of a kit that runs the demo with no network.
- `.github/workflows/live-gates.yml` and `tools/ci/live_gates.sh`: Podman, browser and real-model gates on a CI runner.
- Console CSS: scenario and experiment card titles are no longer cut off; the badge sits above the title (found by the
  projector check at 1280×720 to 1920×1080, 100–150 % zoom).
- Deck: layout fixes on slides 2, 3, 7, 8, 10 and 11 (P5_REPORT section 3); the videos were re-rendered with them.
- `aegislab/THREAT_MODEL.md` section 10.7: one new row for the off-host reviewer key procedure. The countersignature row
  stays **Partial**.

## 2. Accepted history finding

The publication scan of the git history reports **1 FAIL, 0 WARN**:

```
FAIL aegis_token_value  aegislab/tests/test_finale_p2_monitor.py [history:c1d1740265]
```

It is a **fake** token literal in a P2 test (`X-Aegis-Token` header value in commit `c018c52`). It was never a real
token: tokens are random per run and live only on the server. The literal was shortened in the next commit (`947af3e`),
so the scan of the current index is clean (0 FAIL, 0 WARN, 11 allowlist rules). Rewriting published history to remove
it would break every merge commit since; the finding is accepted and stays visible in the scan.

## 3. Residual risks (stated before anyone asks)

| Risk | What would still fail |
|---|---|
| Host compromise | The evidence signing key is a 0600 file of the host user. A kernel exploit that gains that user can forge evidence. The reviewer countersignature defeats this only when the reviewer key never touches the host: **Partial**. |
| Deadline D is host- and model-specific | D = 1400 ms was calibrated on one laptop for Qwen2.5-0.5B. Elsewhere it must be re-calibrated. Too short: more cut-offs. Too long: only latency. |
| No leak detected is not absence | One classifier, one host. Cache, memory-bandwidth and CPU-contention channels were not measured; post-cut-off generation was not measured as a channel. |
| Canary detector gaps | Double encoding, other bases, ciphers, homoglyphs, translation, paraphrase, and a token split across replies. |
| Anomaly thresholds not tuned | Fixed, never trained on adversarial traffic. An attacker below every threshold is not flagged. |
| Capability tokens | No revocation list; the API has no TLS (loopback only). |
| Shared kernel | Containers share the host kernel. gVisor and Kata were not tried (`runsc` not installed). |
| Coverage | One host; one model at full scale (0.5B) plus a reduced 1.5B run; CPU only. GPU and accelerator KV-cache isolation untested. |
| Hosted demo | Render free plan: a cold start of about 24 s after idle, and the site needs venue internet. The offline fallback is the local public demo (`AEGIS_PUBLIC_DEMO=1`, `app.py` on 127.0.0.1). The hosted demo is read-only and cannot run live sandboxes (no Podman on Render). |
| Retired Vercel copy | Still online with the 28 Oct code until its owner deletes or redeploys it. |
| Narration | Synthetic Piper voice. A person must still listen to both videos (FINALE_HUMAN_CHECKLIST). |

Not claimed: production readiness, a third-party audit, invulnerability, model robustness to prompt injection, any
customer or certification.
