# AegisLab

<!-- finale:start -->
> **Grand Finale (Manali, 20–21 Nov 2026) · status on 12 Nov 2026**
>
> - **Finale package:** [`finale_package/`](finale_package/): the 12-slide deck ([PDF](finale_package/Tech_Mavericks_AegisLab_Finale.pdf)), 3-minute, 6-minute and 10-minute talk tracks ([`FINALE_SCRIPT.md`](finale_package/FINALE_SCRIPT.md)), the judge Q&A ([`FINALE_JUDGE_QA.md`](finale_package/FINALE_JUDGE_QA.md)), the one-page handout, caption files, and the recorded terminal transcripts. Every figure comes from [`claims_used_for_finale.json`](finale_package/claims_used_for_finale.json) with its type (LIVE, RE-MEASURED <date> or RECORDED <date>), and `aegislab/evaluation/check_finale_presentation.py` enforces that.
> - **Presented code:** branch `finale/p4-hardening` (commit `9145592`) plus this package; P1–P4 are not yet merged into `main`.
> - **Real model, live:** `bash scripts/real_model_demo.sh` ends with 13/13 checks (LIVE). Re-measured on the finale code: 0 of 104 sessions leaked across sessions while the controls that must leak did (RE-MEASURED 11 Nov 2026). The real-model default is deadline release at t0 + 1400 ms (LIVE), because 250 ms padding leaked against the real model (accuracy 0.945/0.960/0.950, RE-MEASURED 11 Nov 2026).
> - **Public read-only demo:** https://aegislab.vercel.app: browse the evidence, verify a bundle, tamper with a disposable copy. No operator session, no runs, no containers. It serves `main`; the verify fix (finale P1) is live only after the merge.
> - **The rc4 package** at the repository root (`Tech_Mavericks_AegisLab_Submission.pptx` and `.pdf`, `Tech_Mavericks_AegisLab_Pitch_120s.mp4`, `Captions.srt`, `Voiceover_Script.txt`, `Storyboard_Timestamped.txt`, `Judge_QA.md`, `PHASE4_CLAIM_MATRIX.*`) is the **historical** pre-finale submission of 23 Oct 2026, kept unchanged and still checked against its own figures by `check_presentation.py`. See [`RC4_PACKAGE_HISTORICAL.md`](RC4_PACKAGE_HISTORICAL.md).
<!-- finale:end -->

**Secure infrastructure for adversarial AI safety testing.** Red-team attacks, blue-team defences and the model under test run side by side, cannot read each other's protected state, and every run ends with signed evidence that a reviewer can verify on their own machine.

Team **Tech Mavericks** (Abdul Munaf Z, Likhith Sai N, Sreeram Rajesh) · **Hack in Hills '26** · Track 04: *Securing Adversarial AI Safety Testing Infrastructure* (Bayora).

> **Status: working single-host prototype.** It is not a production security system and has not been audited by a third party. Everything below says which results are measured live, which come from saved runs, and where the guarantees stop.

## The problem

An AI safety evaluation puts three parties that do not trust each other into one test:

1. a **red team** that sends attacks and adversarial prompts,
2. a **blue team** that applies defensive policies, and
3. the **client LLM** being evaluated.

If red can see blue's rules, if blue can see red's attack pack before the run, if one session can read another session's data through the model, or if the results can be edited afterwards, the evaluation measures nothing. Track 04 asks for isolation that keeps working, controlled communication, confidential protected state, tamper-evident audit records, deployability on standard hardware, and an honest account of residual risk.

## The approach

AegisLab does not ask the model or a prompt to keep these rules. **The infrastructure enforces them, and tests attack them.**

Code paths below are relative to `aegislab/`.

| Boundary | How it is enforced | Code |
|---|---|---|
| Workload isolation | Rootless Podman per workload: `--network none`, read-only root, all capabilities dropped, no-new-privileges, non-root user, pids/memory/CPU limits, private SELinux labels | `aegis/runtime.py` |
| One controlled channel | Each sandbox gets a private mailbox directory; a trusted broker on the host reads and writes it with no-follow I/O, size and type checks. Identity comes from *which mailbox* a message is in, not from what the message claims | `sandbox/spool.py`, `aegis/runs.py` |
| Role-based control plane | FastAPI with a server-side role gate (operator, reviewer, blue, red, observer); results stay behind the gate until a reviewer releases them | `aegis/api.py` |
| Run lifecycle | `CREATED → FROZEN → RUNNING → SEALED → RELEASED`, or fail-closed `FAILED`. The defence configuration is frozen and attested before the run starts | `aegis/runs.py` |
| Commitments | Red commits to every attack as `SHA-256(nonce ‖ 0x00 ‖ payload)` before it runs | `sandbox/red_agent.py`, `aegis/crypto.py` |
| Model-session isolation | Fresh model worker per run (stub); for a real model, one stateless message per request, prompt cache off, and the broker withholds output carrying another run's canary | `aegis/model_client.py`, `aegis/runs.py` |
| Tamper-evident audit | Hash-chained audit log, chained Ed25519 checkpoints, and a signed **terminal checkpoint** so that truncation is detectable | `aegis/audit.py`, `aegis/store.py` |
| Independent verification | A separate, fail-closed verifier that checks an exported bundle against a pinned public key | `aegis/verify_cli.py` |

Workflow of one run: the **operator** creates the run, the **blue** participant submits a defence configuration, the operator **freezes** it (digests and attestation recorded) and **starts** the run. The **red** sandbox sends committed attacks through its mailbox; the broker routes them to the **blue defence runner** and the **model worker**, records every hop in the audit chain, and returns only what red is allowed to see. The run is **sealed**; a **reviewer** verifies and **releases** it; only then can participants read results. The exported evidence bundle verifies offline.

Full threat table, trust assumptions and residual risk: [`aegislab/THREAT_MODEL.md`](aegislab/THREAT_MODEL.md). Detailed technical reference (API table, verifier options, evaluation harness, design choices): [`aegislab/README.md`](aegislab/README.md) (written 23 Oct; some test counts in it are from earlier phases).

## Requirements

- Linux with **rootless Podman** and cgroups v2. Tested only on **one Fedora host** (kernel 7.2, Podman 5.8.9, crun, SELinux enforcing).
- Python 3.12 or newer (`pyproject.toml`; CI runs 3.14, the public demo on Vercel runs 3.12 from `.python-version`, tested locally with 3.14 and 3.15).
- Network access the first time: PyPI for the Python packages in `requirements.txt`, Docker Hub for `python:3.12-slim`, pulled by digest (`docker.io/library/python@sha256:e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c`, as pinned in `aegislab/Containerfile`).
- No GPU, no model download and no API key for the judge path.

The scripts install nothing globally: they create a project-local `.venv/` and write runtime state under `var/` (both git-ignored).

## Quickstart

```bash
git clone https://github.com/Invinciblx777/HIH.git
cd HIH/aegislab                  # the prototype lives in aegislab/; every command below runs from there
bash scripts/quickstart.sh       # venv, dependencies, sandbox image, full test suite, demo run DEMO-001, strict verification
```

`quickstart.sh` prints one PASS/FAIL line per stage and exits non-zero if any stage or any security test fails. Prerequisite failures (no Podman, not rootless, old Python, no network) name the stage and the fix.

## Judge demo (offline, a few seconds)

```bash
bash scripts/judge_demo.sh            # add --pause to step with Enter, --record out.json for a timestamped transcript
bash scripts/security_demo.sh         # the longer original demonstration
```

What you will see, and what kind of result each one is:

| # | Demonstration | Command / step | Result type |
|---|---|---|---|
| 1 | **Rejected attack.** Red tries to read sealed results and to release the run, a reviewer reads before release, a forged token is used, the red sandbox sends forbidden broker requests, and a hostile container plants a symlink and a FIFO in the broker's mailbox. All are denied; the broker logs the denials | `judge_demo.sh` steps 2–3, `security_demo.sh` step 3 | **LIVE** (real rootless containers, stub model) |
| 2 | **Allowed operation.** A legitimate run is created, frozen, started, sealed and released by the right roles | `judge_demo.sh` step 2, `security_demo.sh` steps 2 and 4 | **LIVE** (stub model) |
| 3 | **Evidence verification.** The released bundle passes strict verification with the key and terminal hash pinned | `judge_demo.sh` step 4, `security_demo.sh` step 5 | **LIVE** |
| 4 | **Tamper rejection.** A copy with entries removed or edited fails verification; the original stays byte-identical | `judge_demo.sh` step 5, `security_demo.sh` step 6 | **LIVE** (on copies) |
| 5 | **Real-model evidence.** Cross-session leak tests on a real model, next to positive controls that are built to leak | `judge_demo.sh` step 6, `security_demo.sh` step 8 | **PRECOMPUTED REAL-MODEL** (saved runs, recomputed from raw files on screen; no model runs during the demo) |
| 6 | **Real model, live.** The same isolation checks with Qwen2.5-0.5B answering live: stateless sessions, a positive control that must leak, the broker withholding that leak (with its audit entry), and strict verification of the bundle. The model server runs in rootless Podman with `--network none` and is reached over a UNIX socket | `scripts/real_model_demo.sh` (about 30 s), `scripts/start_real_model_console.sh` (console) | **LIVE REAL MODEL** (needs the model files, which are not in the repository; see below) |
| — | The Phase 1 broker overwriting the audit log before the fix | `judge_demo.sh` step 3 | **HISTORICAL** (recorded 23 Oct, labelled as such) |

`judge_demo.sh` and `security_demo.sh` use a deterministic **stub** model by design: it makes leakage behaviour testable and keeps the demo offline. Demonstration 6 is the exception; it needs `llama-server` (llama.cpp b11819, CPU) and `qwen2.5-0.5b-instruct-q4_k_m.gguf` outside the repository (default `../../../_models/` from `aegislab/`, or `AEGIS_MODELS_DIR`), and refuses to start if either file's sha256 differs from the one the evidence was recorded with. Step-by-step instructions and expected output: [`docs/JUDGE_GUIDE.md`](docs/JUDGE_GUIDE.md). A recorded transcript of a real successful run is in [`aegislab/evidence/phase4_2026-10-23/judge_demo_transcript.txt`](aegislab/evidence/phase4_2026-10-23/judge_demo_transcript.txt) (a recording, not a live run).

## Interactive prototype console

```bash
bash scripts/start_prototype.sh       # then open the launch link it prints (loopback only; Ctrl-C stops it)
```

The console is a browser interface on the same control plane. The launch link starts a local operator session; the browser never holds a role token. It drives the run lifecycle step by step (create, defence, freeze, start, seal, release) in rootless containers, runs four allowlisted attack scenarios against them, shows the security events, and verifies (and tampers with copies of) the signed evidence through `aegis.verify_cli`. Without Podman it starts in a labelled degraded mode with a recorded replay. Guide: [`docs/prototype/PROTOTYPE_GUIDE.md`](docs/prototype/PROTOTYPE_GUIDE.md). Five-minute judge path: [`docs/prototype/JUDGE_WALKTHROUGH.md`](docs/prototype/JUDGE_WALKTHROUGH.md). Interactive walkthrough of the live lab: [`docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`](docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md).

**With the real model (finale P3, 10 Nov 2026).** The same console, with Qwen2.5-0.5B answering every lab run live:

```bash
bash scripts/start_real_model_console.sh                  # port 8410; model server in rootless Podman, --network none, UNIX socket
bash scripts/start_real_model_console.sh --host-process   # model server as a host process on 127.0.0.1 instead
```

It labels each run "REAL MODEL · LIVE" with the model file, its sha256 prefix, "llama.cpp CPU" and "loopback". The label comes from the run's own frozen manifest. It never falls back to the stub: an unreachable model server makes the run `FAILED`, and errors reach red as the uniform refusal. Its state is separate (`var/console-real`). Ctrl-C stops the console and the model server and deletes the server's key. `scripts/start_prototype.sh` is unchanged and still starts the stub console.

Console session rules (Phase R3 hardening, 26 Oct 2026):

- The launch link works **once** and expires after 2 hours unused. For another one while the console runs: `bash scripts/start_prototype.sh --link`. **End session** in the header returns the browser to read-only.
- The live console is for **one trusted local operator on loopback**. It is not multi-user authentication and must never be exposed on a network or a public URL: it starts real sandboxes and holds the signing key.
- **Public read-only demo:** https://aegislab.vercel.app runs the same console with `AEGIS_PUBLIC_DEMO=1`, which `aegislab/app.py` forces on. You can browse every page, play the recorded replay, run the real independent verifier (`aegis.verify_cli`) on the shipped bundles, and tamper with disposable copies to watch the verifier reject them. You cannot start live runs: there is no Podman there, and live mode stays off even where Podman exists. There is no operator session and no launch code, and every other state-changing request gets HTTP 403. Verifier requests are rate-limited (HTTP 429): 10 per minute per client IP and 60 per minute overall, for each server instance. The site holds no evidence of its own; its keys and tokens are temporary files in `/tmp`. `AEGIS_PUBLIC_DEMO=1` is the only setting that lifts the loopback Host guard, and it turns off every write at the same time (a bare `VERCEL` variable no longer lifts the guard).
- Cookies are not isolated by port on `127.0.0.1`: use a dedicated browser profile and do not browse other local web services while the console runs. Other accepted limits: [`docs/prototype/R3_SECURITY_REVIEW.md`](docs/prototype/R3_SECURITY_REVIEW.md) section 6.
- Container-free release gates (the same script the GitHub workflow runs): `bash scripts/release_gates.sh --with-browser --strict`. Release record: [`docs/release/PHASE_R35_RELEASE_REPORT.md`](docs/release/PHASE_R35_RELEASE_REPORT.md).

## Verify the evidence yourself

```bash
. .venv/bin/activate
python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released --run-id DEMO-001 --expect-state RELEASED   # exit 0
python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001 --run-id VAL-001 --expect-state RELEASED      # exit 0
python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3 --run-id VAL-001 --expect-state RELEASED   # exit 1: tampered
python evaluation/check_claims.py      # recomputes the quoted figures from the raw evidence files
```

The verifier is **fail-closed**: a log without a signed terminal checkpoint is never reported as valid. `evidence/DEMO-001/` is the original 15 Oct bundle in the legacy format; strict verification rejects it by design.

## Measured results

From the evidence in `aegislab/evidence/` (one Fedora host, CPU only). Every figure is recomputed from raw files by `python evaluation/check_claims.py`. Validation commands, exit codes and anything skipped: [`docs/VALIDATION_2026-10-25.md`](docs/VALIDATION_2026-10-25.md); per-phase detail in [`PHASE2_SECURITY_REPORT.md`](PHASE2_SECURITY_REPORT.md), [`PHASE3_LLM_SECURITY_REPORT.md`](PHASE3_LLM_SECURITY_REPORT.md) and [`PHASE4_PRESENTATION_REPORT.md`](PHASE4_PRESENTATION_REPORT.md).

- **Role boundaries:** a 560-attempt role × operation × lifecycle-state matrix: 419 / 419 expected denials denied, 141 / 141 expected successes succeeded, 0 unexpectedly permitted.
- **Hostile mailbox attack** from a real rootless container (symlink and FIFO planted at guessed names): blocked; the audit log stays intact and the broker never blocks.
- **Audit integrity:** a released run verifies strictly; tampered copies are rejected.
- **Overhead:** 2.59–2.84 ms median per broker hop (idle host, stub model).
- **Timing side channel (stub model, three executions):** a simple classifier reads the defence's decision from response time with 0.795–0.800 accuracy unpadded; 250 ms response padding lowers it to 0.495–0.555, at +198 to +201 ms per answered request. This weakens one classifier; it does **not** show the channel is gone.
- **Timing side channel, real model (three executions, 11 Nov 2026):** balanced classes, n = 200 per setting and execution, every payload in both classes.
  - 250 ms padding does **not** hide the decision: accuracy 0.945–0.960 (p=0.001 in each).
  - Deadline release, where every reply leaves at a fixed t0 + D calibrated from the model's latency, gave 0.495, 0.545 and 0.575 against majority baselines of 0.515, 0.540 and 0.515. No leak was detected by the pre-declared rule; that is not a proof of absence.
  - Cost: +519 to +621 ms per answered request, and 3–8 % of model answers cut off at the deadline (red sees a refusal).
  - Deadline release is now the default for a real-model backend (D = 1400 ms, `AEGIS_TIMING_DEADLINE_MS`); the stub keeps 250 ms.
  - Raw files: `aegislab/evidence/finale_p4_2026-11-11/timing_deadline/`. The single 10 Nov execution (`finale_p3_2026-11-10/timing_real_model/`) is superseded.
- **Real model — re-measured 11 Nov 2026 on the finale P4 code** (Qwen2.5-0.5B Q4_K_M, llama.cpp b11819 on CPU, loopback only): 0 / 104 sessions recovered another session's canary (1,040 trials); full pipeline 0 / 26 runs. The positive controls that are built to leak did leak (16 / 16 and 13 / 16 sessions), so the probes can detect a leak. These are the same figures as on 10 Nov and 23 Oct. Two secondary figures vary between dates, and all are reported: the pipeline's context-sharing control leaked in 2 / 4 runs (10 Nov: 3 / 4; 23 Oct: 2 / 4), and the cache-off latency AUC was 0.41 / 0.56 (10 Nov: 0.41 / 0.47; 23 Oct: 0.52 / 0.42). Raw runs: `aegislab/evidence/finale_p4_2026-11-11/llm_final/`; the 10 Nov and 23 Oct runs stay in the repository and are still checked.
- **Containers never run as the key owner (11 Nov 2026):** every red, blue, model-worker and model-server container runs as container UID 900 on its own subordinate host UID (`--userns auto`), sampled live with `podman top` and `/proc`; a container that bind-mounts the signing key cannot read it (errno 13). `aegislab/evidence/finale_p4_2026-11-11/userns_proof_final/`.
- **Real model — live.** `scripts/real_model_demo.sh` and the real-model console answer with the model in real time. The model server is hardened and sandboxed; what its flags close, and what they cannot close, is in `aegislab/THREAT_MODEL.md` section 9.

## Known limitations

Stated here because a security result is only as credible as its limits.

- **Trusted broker and signing key.** The broker sees everything and signs the checkpoints. A compromised broker or a stolen key can produce false but consistent records. Since finale P4 a reviewer countersignature (`verify_cli --require-countersignature`) catches a re-signed history, but only when the reviewer key is held off the broker host; by default it is on the same host (Partial).
- **Global role tokens.** The four role tokens are per role, not per run, and are local demo tokens (`var/keys/tokens.json`). Since finale P4 the operator and reviewer can issue signed capability tokens limited to one run, a subset of operations and at most 1 h; they cannot be revoked before expiry except by replacing the capability key. `AEGIS_DEMO_MODE=1` hands every token to any local caller: demo only. The prototype console refuses to start with it: it keeps the tokens on the server and gives the browser a loopback operator session instead (one local operator, not multi-user authentication).
- **One host.** Validated on a single Fedora machine. Containers share the host kernel; a kernel or runtime escape is out of scope. Since finale P4 an escaped container process is a subordinate UID that cannot read the signing key; a kernel exploit that also gains the host user still can. gVisor was not tried (not installed on the test host).
- **Small model, few prompts.** One 0.5B model on CPU and ten probe wordings; three probes stayed silent even when sharing was on purpose. Zero observed leaks is not proof of zero risk (one-sided 95% upper bound: 2.84% of sessions for this setup).
- **Detector gaps.** Since finale P4 another run's canary is also withheld in base64 (standard or URL-safe, any offset), hex, rot13, reversed, digit-split and spelled-out form. It still misses double encodings, other bases, ciphers, homoglyphs, translation, paraphrase and a token split across replies.
- **Timing.** Padding weakens one measured classifier on the stub model. With a real model, 250 ms buckets do not hide it; deadline release (the real-model default since finale P4) showed no leak in three executions, but D = 1400 ms was calibrated on one host for one model and must be re-calibrated elsewhere. Other side channels (cache, memory bandwidth, scheduling, power) remain shared.
- **GPU and accelerator KV-cache isolation were not tested.** Only CPU inference was exercised. The proposed GPU boundary is described in `aegislab/README.md` ("GPU inference boundary").
- **Saved and live real-model results.** The judge and security demos show the real-model numbers from saved runs; they never run a model. `scripts/real_model_demo.sh` and `scripts/start_real_model_console.sh` do run it live. Both these scripts and the experiments need a local `llama-server` binary and a GGUF model file (not included; nothing is downloaded by the repo). Re-running E1–E5 took 33 minutes on 11 Nov (`evaluation/llm_isolation.py`).
- An earlier CPU-contention measurement (+37–52% round-trip time) did not reproduce in later runs (−5% to +1%).

## Security and responsible use

- Run the control plane on **loopback only** (`127.0.0.1`). Never expose the API to a network: it can launch adversarial workloads, and the demo tokens are not real authentication.
- All attack packs, canaries and keys in this repository are synthetic. Test keys such as `sk-test-SECRET-KEY-…` in `tests/` are fixtures that open nothing.
- Report vulnerabilities as described in [`SECURITY.md`](SECURITY.md).

## Repository layout

The repository is the release package. The prototype is in `aegislab/`; the reports, deck and video sit beside it, and the claim checkers read them from there.

```
aegislab/                    the prototype (start here)
  aegis/                     control plane: api.py, runs.py (lifecycle, broker, gate), audit.py, crypto.py, runtime.py, evidence.py, verify_cli.py, model_client.py
  sandbox/                   code that runs inside the containers (standard library only)
  samples/                   synthetic attack pack and defence configuration
  scripts/                   quickstart.sh, judge_demo.sh, security_demo.sh, start_prototype.sh (console), demo_run.py
  tests/                     pytest suite (security regression, Phase 2 attack tests, Phase 3 LLM tests, Podman-based tests)
  evaluation/                experiment harnesses; check_claims.py and check_presentation.py recompute every quoted figure
  evidence/                  dated evidence sets, each with its own README; never edited after recording
  web/                       web/console: the interactive prototype console (aegis/console.py); web/fonts: deck and video fonts
  THREAT_MODEL.md, README.md threat table and technical reference
README_FIRST.md              release-package guide (rc4, 23 Oct)
PHASE2/3/4 reports, Judge_QA.md, PHASE4_CLAIM_MATRIX.md, VALIDATION_ADDENDUM_2026-10-22.md, ...   reports; older ones keep the figures of their date
Tech_Mavericks_AegisLab_Submission.pptx / .pdf, Tech_Mavericks_AegisLab_Pitch_120s.mp4, Captions.srt, Voiceover_Script.txt, Storyboard_Timestamped.txt
presentation_src/            deck and video build sources (includes the official event template)
assets/                      15 Oct diagrams and screenshots (historical figures; not used by the current deck)
MANIFEST.sha256              SHA-256 of the 259 release files (rc4 minus the legacy site): sha256sum -c MANIFEST.sha256
docs/                        judge guide, validation record, and docs/prototype (console guide, walkthrough, Phase R1 report)
tools/publication_scan.py    pre-publication secret and private-data scan (git index and history)
```

## Licence

Code: MIT, see [`LICENSE`](LICENSE). Fonts in `aegislab/web/fonts/`: SIL Open Font License 1.1, see [`aegislab/web/fonts/OFL.txt`](aegislab/web/fonts/OFL.txt). The event logos and `presentation_src/official_template.pptx` come from the official Hack in Hills '26 template and are not covered by the MIT licence. Python dependencies: FastAPI (MIT), Uvicorn (BSD-3-Clause), cryptography (Apache-2.0 / BSD).
