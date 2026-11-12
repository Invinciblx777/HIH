# AegisLab · Grand Finale judge Q&A

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora). Built from the rc4 `Judge_QA.md` (23 Oct 2026, now historical) plus everything finale P1–P4 changed.

- **Code:** `main`, with finale P1–P5 merged on 12 Nov 2026. Screenshots and terminal recordings were made on commit `9145592`.
- **Figures:** every figure comes from `finale_package/claims_used_for_finale.json` and carries its type: **LIVE** (produced by the presented code when it runs; the number is the 12 Nov rehearsal's), **RE-MEASURED <date>** (measured again on the finale code) or **RECORDED <date>** (not re-run). `aegislab/evaluation/check_finale_presentation.py` checks this file against the claims file.
- **Evidence paths** are relative to the repository root unless they start with `docs/finale/`, which is in the team workspace next to the repository.

## The questions most likely to challenge the story

**1. How do you know isolation works, and not just that the model refused?**
Three things. The detector looks for the planted canary and its fragments in the raw model output, not for refusals. The same probes recover a canary when context is shared on purpose: 16 of 16 sessions with shared history and 13 of 16 sessions through a context-sharing gateway (RE-MEASURED 11 Nov 2026). With nothing planted: 0 of 320 negative-control trials (RE-MEASURED 11 Nov 2026). Evidence: `aegislab/evidence/finale_p4_2026-11-11/llm_final/INDEX.json`.

**2. What do the zero-leak results establish, and what not?**
Direct adapter: 0 of 104 sessions and 0 of 1040 isolation trials recovered another session's canary (RE-MEASURED 11 Nov 2026). The one-sided 95% upper bound is 2.84% of sessions and 0.29% of trials (RE-MEASURED 11 Nov 2026). That bounds the leak rate for these probe wordings, this model, this server build and these flags. "No leak detected" is never "no leak". Full pipeline (broker, sandboxes, real model, E2): 0 of 26 isolation runs, 312 attacks, 0 reached red (RE-MEASURED 11 Nov 2026); in the context-sharing control the model leaked in 2 of 4 runs and the broker withheld 17 attacks withheld, 0 reached red (RE-MEASURED 11 Nov 2026). Prompt cache (E3): cache off, cached tokens in 0 of 120 trials (RE-MEASURED 11 Nov 2026); cache on (control) AUC 1.00/1.00 (RE-MEASURED 11 Nov 2026); cache off, latency AUC 0.41/0.56 (RE-MEASURED 11 Nov 2026). Evidence: `aegislab/evidence/finale_p4_2026-11-11/llm_final/INDEX.json`, `aegislab/evidence/finale_p4_2026-11-11/README.md`.

**3. Why did the 250 ms timing result change?**
With the stub model, 250 ms response buckets bring a latency classifier to chance: 0.435–0.540 at 250 ms (RE-MEASURED 11 Nov 2026). The stub answers in near-constant time. A real model's latency spans many 250 ms buckets, and refusals never reach the model, so with the real model the refusal decision stayed readable: 1.000 at 250 ms in one execution (RECORDED 10 Nov 2026), confirmed in three balanced executions: accuracy 0.945/0.960/0.950, p = 0.001 (RE-MEASURED 11 Nov 2026). Our own harness found this; the old "padding brings it to chance" statement now always says "stub model". Evidence: `aegislab/evidence/finale_p3_2026-11-10/timing_real_model/`, `aegislab/evidence/finale_p4_2026-11-11/timing_deadline/aggregate.json`.

**4. Why D = 1400 ms (LIVE), and what does deadline release cost?**
Every reply, answered or refused, leaves at t0 + D; a model that has not answered by D minus the reserve is cut off and red gets the uniform refusal. D was calibrated per execution from the measured latency: 1300/1400/1300 ms (RE-MEASURED 11 Nov 2026); the default is the largest, D = 1400 ms (LIVE, `aegislab/aegis/runs.py`, overridable with `AEGIS_TIMING_DEADLINE_MS`). Result: accuracy 0.495/0.545/0.575 against majority baselines 0.515/0.540/0.515, p = 0.560/0.197/0.044 (RE-MEASURED 11 Nov 2026). Cost: +519 to +621 ms per answered request and 3–8 % of model calls cut off (RE-MEASURED 11 Nov 2026). D is host- and model-specific; another machine must re-calibrate (`aegislab/evaluation/timing_deadline.py`, phase one).

**5. One deadline p-value is below 0.05. Why is that not a leak?**
The third execution gave p = 0.044 (RE-MEASURED 11 Nov 2026). We declared before measuring that a leak needs p below 0.05/9 = 0.0056 (RE-MEASURED 11 Nov 2026) in any execution (Bonferroni over nine tests). It is below 0.05 and above that threshold, so the verdict is "no leak detected (inconclusive as to absence)". We did not move the threshold and we show the number. Evidence: `aegislab/evidence/finale_p4_2026-11-11/timing_deadline/aggregate.json`.

**6. What if the broker or the signing key is compromised?**
A compromised broker can sign a false but consistent record; the verifier cannot tell. The finale work moved the key out of the containers' reach: every container runs as container UID 900 on its own host UID, never the broker's UID 1000, and a container that mounts the key gets errno 13 (RE-MEASURED 11 Nov 2026; `aegislab/evidence/finale_p4_2026-11-11/userns_proof_final/`). The key is still an unencrypted 0600 file of the host user: a kernel exploit that becomes that user can forge evidence. The reviewer countersignature refuses a broker-key forgery, but a forger holding both keys still succeeds (security demo step 7, 2 stated limits, LIVE). So the countersignature is **Partial**: it helps only while the reviewer key lives on another machine. KMS/HSM and rotation: future work. Evidence: `docs/finale/P4_REPORT.md` section 5, `aegislab/THREAT_MODEL.md` section 10, `finale_package/terminal/t3_security_demo.txt`.

**7. Containers share the kernel. Did you try gVisor or Kata?**
No. `runsc` is not installed on the test host and the finale rules allowed no downloads, so gVisor is "not tried", not "failed". A kernel exploit from a tenant container defeats the boundary; with the F4 split it lands on a subordinate UID that cannot read the key, but a further escalation to the host user reaches it. Evidence: `docs/finale/P4_REPORT.md` OPTIONAL 9, `aegislab/THREAT_MODEL.md` row 8.

**8. Does the canary detector catch encoded leaks?**
Single encodings, yes, since the finale work: base64, hex, rot13, reversed, split and spelled-out forms of another run's canary are withheld, and the live demo shows a base64-only leak withheld (13/13 checks, LIVE). Still missed: double encodings, other bases, ciphers, homoglyphs, translation, paraphrase, and a token split across replies. The detector is the second line; server-side isolation (stateless requests, cache off) is the first. Evidence: `aegislab/aegis/canary_scan.py`, test `P3B02d` (double encoding, LIMIT), `docs/finale/P4_REPORT.md` MUST 3.

**9. How many models did you test?**
One at full scale: Qwen2.5-0.5B Q4_K_M (RE-MEASURED 11 Nov 2026). One reduced run with Qwen2.5-1.5B (E1 and E3 only): 0 of 280 isolation trials, 0 of 28 sessions, controls 4 of 4 and 3 of 4 (RECORDED 10 Nov 2026, `aegislab/evidence/finale_p3_2026-11-10/llm_qwen2.5-1.5b/`). Both on CPU with llama.cpp. Larger models, other servers and other builds are untested.

**10. GPU?**
Untested. Everything ran on CPU. GPU memory, accelerator KV-cache and CUDA-context isolation are not claimed. Evidence: `aegislab/THREAT_MODEL.md` section 9.

**11. Are the anomaly detectors tuned?**
No. 6 detectors (LIVE) have fixed thresholds chosen from the scripted agent's behaviour and written rationales (`aegislab/aegis/anomaly.py`), not tuned on adversarial traffic. An attacker who stays below every threshold is not flagged. Detectors never change a reply, and alerts go into the signed log without opening a channel to red. Evidence: `docs/finale/P4_REPORT.md` section 4.

**12. Can a capability token be revoked?**
Not yet. Tokens are run-scoped, operation-scoped and expire within an hour; only the reviewer issues reviewer tokens, so the operator cannot mint the right to release; there are no delegation chains. There is no revocation list, and the API has no TLS (it is loopback-only). Evidence: `aegislab/aegis/captoken.py`, `docs/finale/P4_REPORT.md` SHOULD 6.

**13. Why is the public demo read-only?**
A live operator console on a public URL would hand run control (create, start, release) to anyone with the link. So https://aegislab-demo.onrender.com runs with `AEGIS_PUBLIC_DEMO=1` forced in `aegislab/app.py`: no launch link, no session, every write refused except bundle verify and tamper on a disposable copy, live execution off, rate-limited per client and overall. Visitors can verify a real bundle and watch a tampered copy fail. It runs on Render from `main` (P1 fix included). The per-client limit trusts only `CF-Connecting-IP`, which Render's edge sets; a forged `X-Forwarded-For` does not open a new allowance. Evidence: `docs/finale/P1_REPORT.md`, `docs/finale/P6_REPORT.md`, `aegislab/tests/test_finale_p1_public_demo.py`, `aegislab/tests/test_finale_p6_render.py`.

**14. Is the real model really live in the demo?**
Yes. `scripts/real_model_demo.sh` and the console started with `scripts/start_real_model_console.sh` use llama.cpp in a rootless container with no network, and nothing falls back to the stub: 13/13 checks and the browser run 21/21 browser checks (LIVE). The run card shows "REAL MODEL · LIVE" with the model file and its sha256 prefix. Transcripts: `finale_package/terminal/t1_real_model_demo.txt`, `finale_package/terminal/t6_real_model_console_check.txt`.

## Integrity of the evidence

**What does strict verification check?**
Chain, checkpoint signatures, the signed terminal checkpoint binding the final entry and state, a pinned key and terminal hash, and, if required, the reviewer countersignature. Recorded live on the presented code: strict verify exit code 0, a one-field edit of a copy exit code 1 (LIVE, `finale_package/terminal/t5_verify_cli.txt`). Tamper suite: 19/19 tamper categories detected in 30/30 trials; CLI 10/10 genuine bundles accepted, 40/40 tampered copies rejected (RE-MEASURED 11 Nov 2026, `aegislab/evidence/finale_p4_2026-11-11/validation/audit_tamper.json`).

**Does any test fail intermittently?**
One lifecycle stress test, rarely and only under load: many denied reads racing a release. The release check read the audit log and then the reviewer vault while a denied read was appended and checkpointed between the two reads, so the check refused the release. It fails closed: the run stays SEALED, nothing is released, and an independent `verify_cli` run on the run directory passes afterwards. The console cannot trigger it. A fix (one consistent read under the audit file lock) is planned after the finale; it touches hash-pinned files. Evidence: `docs/release/FINALE_RELEASE_NOTES.md` section 3.

**Why is real-model red in CI?**
The deadline D = 1400 ms (LIVE) was calibrated on the presenting laptop, and D is host- and model-specific (a P4 residual risk, question 4). On the smaller GitHub runner enough answers per run miss the deadline and are cut off that the positive control has nothing to detect; the deadline was not changed for CI. On the presenting laptop `scripts/real_model_demo.sh` passes 13/13 checks (LIVE). Evidence: the P7 logs `round2/logs/finale_p7/06_pr16_real_model_artifact/real-model-gate-logs/` (runner, one cut-off per `BrokenPipeError`) and `round2/logs/finale_p7/30_kit/04_restored_network_up.log` (laptop), in the team workspace; `docs/finale/P6_REPORT.md` section 13.

**Access control?**
Role, operation and state matrix: 560 attempts, 419/419 denied, 141/141 allowed, none unexpectedly permitted (RE-MEASURED 11 Nov 2026, `aegislab/evidence/finale_p4_2026-11-11/role_matrix_extended.json`). API matrix: 181/181 unauthorized cases denied, 92/92 traversal rejected (RE-MEASURED 11 Nov 2026).

**Can red signal blue through the monitoring stream?**
Not any more. Participants and the public see run-level lifecycle events only until the run is SEALED; per-attack alerts and refusal reasons go to the operator and reviewer only, and the stream never carries a red-chosen string. Remaining: counts and lifecycle timing are visible. Evidence: `docs/finale/P2_REPORT.md` F3, `aegislab/THREAT_MODEL.md` row 9.

**Can a tenant flood the broker?**
Per-tenant mailbox quotas: 2,100 messages per run, 400 per 10 s, 32 MiB, 512 outbox entries (LIVE). Over any limit the tenant is cut off, `mailbox.quota_exceeded` is recorded, and the run seals incomplete. Evidence: `aegislab/aegis/runs.py` `MailboxQuota`.

## Problem fit, feasibility, reproduction

**Which Track 04 requirement does AegisLab address?**
All six evaluation objectives: isolation that keeps the system working, leakage prevention, audit integrity, deployability, LLM-native threats, and quantified residual risk. The weakest remaining areas are host-level key custody and hardware isolation, both on the residual-risk slide.

**Why not just separate containers?**
Containers are the primitive. You also need a single mediated channel whose identity cannot be spoofed, a configuration frozen before attacks run, attacks committed in advance, stateless model calls, results sealed until release, and evidence an outsider can verify.

**Is the deployment reproducible?**
One Fedora laptop, rootless Podman, no root daemon. The sandbox base image is pinned by digest, the model file and the llama.cpp server binary are checked by sha256 before use, and `pyproject.toml` and `uv.lock` were corrected in finale P4. Nothing is downloaded at the venue. Evidence: `docs/finale/P4_REPORT.md` MUST 5, `aegislab/Containerfile`, `aegislab/aegis/runtime.py`.

**Can I reproduce it?**
`cd aegislab && bash scripts/quickstart.sh`, then `bash scripts/judge_demo.sh` (17/17 checks, LIVE, stub model, seconds, offline), `bash scripts/security_demo.sh` (35/35 checks, LIVE), and `.venv/bin/python evaluation/check_claims.py` (357/357 checks, LIVE). The real-model demo needs the model and server files next to the repository (`_models/`, not committed). Tests on this branch: 702 tests passed, 18/18 browser tests (RECORDED 12 Nov 2026).

**What is not claimed?**
Production readiness, a third-party audit, invulnerability, model robustness to prompt injection, GPU or physical KV-cache isolation, protection against a compromised broker, any customer, partnership or certification.
