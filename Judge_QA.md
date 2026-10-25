# AegisLab: judge Q&A (Phase 4 candidate)

Team Tech Mavericks · Hack in Hills ’26 · Track 04 (Bayora). Every figure below is recomputed from raw files by `aegislab/evaluation/check_claims.py` and `aegislab/evaluation/check_presentation.py`; `PHASE4_CLAIM_MATRIX.md` maps each claim to its artifact, run ID and limitation. Results from the real-model experiments are **precomputed** (recorded 23 Oct 2026, saved under `aegislab/evidence/phase3_2026-10-23/llm/`); nothing in the demo runs a model.

## The five questions most likely to challenge the story

**1. How do you know isolation works, rather than the model merely refusing the prompt?**
Three separate things. (a) The detector looks for the planted canary, its digits and fragments in the raw output, not for refusals. (b) Positive controls: the same probes, model and detector recover a planted canary when context is shared on purpose: 16 / 16 sessions with shared history, 13 / 16 through a context-sharing gateway. (c) A negative control (nothing planted) gives 0 / 32 sessions, 320 trials, so the detector does not fire on coincidence. Refusal is also counted separately: in the injection experiment, 39 of the 69 attacks that reached the model drew a refusal-like reply, and we score that as model behaviour, not as a control. What we count is information flow: 72 attacks, 0 protected values in red-visible output or monitoring. Artifacts: `P3-20261023T084629Z-E1_canary_matrix`, `P3-20261023T054116Z-E4_injection_output_isolation`.

**2. How did the shared-context positive controls show the leakage tests can detect a leak?**
Because with context shared they do detect it, in two different set-ups (history sent to the server, and a gateway that hands other sessions' messages to the model), at the same place where the isolation cells are measured. They also exposed a weakness we report instead of hiding: three probes, Q01, Q08, Q10 (3 of 10), stayed silent even under deliberate sharing, so their zeros carry no weight; and our first gateway control was insensitive (it detected 0 of 2) and was replaced before any isolation result was accepted (`evidence/phase3_2026-10-23/dev_smoke/README.md`). The full pipeline has the same kind of control: with the gateway in front, 2 / 4 runs had a foreign canary in raw model output, the broker withheld 15 attacks, and 0 reached red.

**3. What do 0 of 1,040 trials establish, and what remains uncertain?**
Direct-adapter isolation: 0 / 104 sessions (0 of 1,040 trials) recovered another session's canary. The one-sided 95% upper bound is 2.84% of sessions (0.29% of trials; trials in a session share a canary, so the session figure is the conservative one). That bounds the leak rate for these ten probe wordings against one 0.5B model on one server build with these flags. It does not prove zero risk, and it says nothing about an adaptive or multi-turn attacker, a model that follows instructions better, other cache settings, or hardware state. Full pipeline: 0 / 26 isolation runs (312 attacks) with a foreign canary in raw model output, 0 / 4 negative-control runs.

**4. What is and is not proven about prompt caching, GPU state and physical KV-cache side channels?**
Exercised: the llama.cpp CPU prompt/KV cache in RAM (experiment E3). With `cache_prompt` true a second session can tell whether a guess matches an earlier prompt: cached tokens 119 vs 99 (median), AUC 1.00 for cached tokens and for client latency. AegisLab sends `cache_prompt: false`: cached tokens appeared in 0 / 120 trials, and in 0 of 14 after a process restart. Not tested: GPU memory, CUDA contexts, accelerator KV cache, paged-attention block sharing, the host `--cache-ram` setting, hardware side channels. An operator can still re-open the oracle through `AEGIS_MODEL_EXTRA_JSON` (gap G5, recommended guard not yet built). We do not claim GPU or KV-cache isolation.

**5. What happens if the trusted broker or the signing key is compromised?**
A compromised broker can sign a false but internally consistent record; the verifier cannot tell (test `P2A20`). Someone holding the signing key who replaces every retained copy produces history that verifies, unless the reviewer has an independent trusted terminal commitment: the terminal hash noted at release, checked with `--expect-terminal-hash` (test `P2A11`); the key itself must be pinned with `--pubkey`, otherwise the verifier says the key came from the bundle and is not pinned (test `P2A10`). `scripts/security_demo.sh` step 7 prints the key-thief case as `[LIMIT]`, not as a pass. A kernel or runtime escape defeats the isolation as well. These are trust assumptions, not defects we claim to have solved.

## The earlier broker defects and why the fixed code prevents them

Found by our own Phase 2 attacks (`PHASE2_SECURITY_REPORT.md`; 13 findings, 5 HIGH). Recorded before-fix evidence: `aegislab/evidence/phase2_2026-10-23/before_fix/`.

| Defect | What a hostile tenant could do | Why it no longer works | Regression tests |
|---|---|---|---|
| P2-01 predictable temp name in the tenant-writable mailbox | A symlink or hard link at the guessed name made the broker overwrite the audit log (shown from a real container) | Unpredictable temp name, `O_CREAT\|O_EXCL\|O_NOFOLLOW` relative to a directory descriptor; whatever sits at the final name is replaced | P2B01, P2B02, P2B06, P2C02 |
| P2-02 whole spool directory mounted read-write | Rename `in/`, put a symlink in its place; every later broker write followed it | `in/` and `out/` are separate mount points a tenant cannot rename or remove; the broker opens them with `O_NOFOLLOW\|O_DIRECTORY` | P2B05, P2C01 |
| P2-03 FIFO at the temp name | `open()` blocked forever; the run hung | `O_EXCL` fails instead of blocking; `O_NONBLOCK` | P2B03, P2B32 |
| P2-05 denied read racing a release | An anonymous caller made a genuine release fail verification | After the chain is closed only the terminal checkpoint may be written; a second terminal checkpoint is refused | P2L10, P2L11 |

The live demo (`bash scripts/judge_demo.sh`, step 3) repeats the symlink, FIFO and directory attacks from a real rootless container against the current broker. The Phase 1 outcome (`victim audit.jsonl intact: False`) is shown from the recorded file and labelled HISTORICAL; the old code is not in this tree and is not re-run.

## Honest limits

**Does the canary detector cover every representation of a secret?**
No. It recognises the planted token, its 12 digits, separated digits and 8-digit fragments of other runs' canaries, plus registered control-plane secrets. A model or gateway that re-encodes a canary (base64, a cipher, spelled-out digits) is not recognised (test `P3B02d`, marked LIMIT). The 0.5B model was asked for base64 and did not comply, so this was not exercised against the real model. Server-side isolation remains the primary control; the detector is a second line.

**Does the prompt-injection result show the model is robust?**
No. The model had no system prompt, tools, memory or protected data, so there was nothing to reveal. The result is that nothing crossed a boundary: 72 attacks (69 reached the model), 0 protected values in red-visible output or monitoring, 282 / 282 replayed model-generated gate messages denied.

**Does the timing mitigation remove the timing channel?**
No. A single-threshold classifier separating refused from answered responses reaches held-out accuracy 0.795–0.800 without padding; with 250 ms buckets 0.495–0.555, not distinguishable from chance in these runs, at a cost of +198 to +201 ms per answered request. That lowers one classifier's accuracy; one weak classifier and a constant-latency stub do not establish that the channel is gone.

**What does it cost?**
Broker mailbox hop: 2.59–2.84 ms median on an idle host (stub model, three executions). Real model on CPU: median about 349 ms per request with the cache off (E3). The Phase 1 CPU-contention increase did not reproduce in three Phase 2 executions on a quiet host; the two sets disagree and no immunity to interference is claimed.

**What happens when the model server fails?**
9 / 9 failure-handling checks hold (E5), including a real SIGKILL mid-request: a sustained outage fails the run closed with a verifying terminal checkpoint and no readable artifacts; isolated errors seal the run as incomplete with the count in the signed log. There is no fallback to the stub. Gap G4: a run sealed incomplete is still releasable; the report says so.

**What about access control?**
A 560-attempt role × operation × state matrix: 419 / 419 expected denials denied, 141 / 141 expected successes succeeded, 0 unexpectedly permitted, 0 secret markers (`evidence/phase2_2026-10-23/role_matrix_extended.json`). Not covered: operations that launch containers, and run-scoped identities (tokens are global per role).

## Audit integrity

**What does strict verification check, and what is the difference between in-progress and complete?**
Chain, checkpoint signatures, the signed terminal checkpoint binding the final entry and state, and (when given) the pinned key and terminal hash. A log still being written can be checked only with `--allow-in-progress`; that reports `terminal_verified: false` and is never counted as a strict pass. The legacy `evidence/DEMO-001` (before terminal checkpoints) is rejected by design; `evidence/closeout_2026-10-22/DEMO-001_released` passes.

**Can you show a tampered copy failing?**
Yes, `bash scripts/judge_demo.sh` step 5: the last 3 entries removed from a copy of the released bundle; the verifier reports truncation and exits 1; the original still verifies.

## Problem fit and positioning

**Which Track 04 requirement does AegisLab address?**
Red team, blue team and the model under test running together without exposing protected state or opening side channels, with evidence a third party can check. Mapping: isolation that keeps the system working (no-network sandboxes, a few ms per broker hop); leakage prevention (brokered mailboxes, sealed artifacts, withholding of foreign canaries); audit integrity (hash chain, signed terminal checkpoint, strict verifier); deployability (rootless Podman on stock Linux); LLM-native threats (stateless adapter, canary experiments, cache experiment); residual risk (`aegislab/THREAT_MODEL.md`).

**Why not just separate Docker containers?**
Containers are the primitive. You also need a single mediated channel whose identity cannot be spoofed, a configuration frozen before attacks run, attacks committed in advance, results sealed until release, and evidence that someone outside the team can verify.

**How do blue-team people and the defence runner differ?**
The runner is an isolated workload that reads a frozen read-only config. Blue-team people get 403 on artifacts until release.

## Feasibility and scope

**What runs today?**
A single-host prototype: Python control plane, rootless Podman sandboxes with no network, file-mailbox broker, frozen config, commitments, hash-chained signed audit, result gate, web console, strict verifier, a deterministic stub model, and an optional real-model adapter (loopback only, key never logged, no fallback to the stub).

**What is simulated or not claimed?**
By default the model is a deterministic stub, not an LLM. Identities are local demo tokens. State is JSON files. There is no public deployment, no customer, no partnership and no certification. Proposed items (signer in its own process, run-scoped identities, microVMs, a GPU model server behind its own boundary) are not built.

**Can I reproduce it?**
`bash scripts/quickstart.sh` (8 stages incl. the full test suite), `bash scripts/judge_demo.sh` (seconds, offline), `bash scripts/security_demo.sh` (the longer original demo), `python evaluation/check_claims.py` and `python evaluation/check_presentation.py`. Validation results and every command, exit code and skipped check are in `PHASE4_PRESENTATION_REPORT.md`. Only one host and distribution were tested.

**Market and customers?**
Not part of this deck. Earlier submissions listed assumptions only; we have no interviews, no agreement with Bayora and no revenue figures.
