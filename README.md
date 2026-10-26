# AegisLab

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
- Python 3.11 or newer (tested with 3.14).
- Network access the first time: PyPI for the Python packages in `requirements.txt`, Docker Hub for `python:3.12-slim`.
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
| — | The Phase 1 broker overwriting the audit log before the fix | `judge_demo.sh` step 3 | **HISTORICAL** (recorded 23 Oct, labelled as such) |

The demos use a deterministic **stub** model by design: it makes leakage behaviour testable and keeps the demo offline. Step-by-step instructions and expected output: [`docs/JUDGE_GUIDE.md`](docs/JUDGE_GUIDE.md). A recorded transcript of a real successful run is in [`aegislab/evidence/phase4_2026-10-23/judge_demo_transcript.txt`](aegislab/evidence/phase4_2026-10-23/judge_demo_transcript.txt) (a recording, not a live run).

## Interactive prototype console

```bash
bash scripts/start_prototype.sh       # then open the launch link it prints (loopback only; Ctrl-C stops it)
```

The console is a browser interface on the same control plane. The launch link starts a local operator session; the browser never holds a role token. It drives the run lifecycle step by step (create, defence, freeze, start, seal, release) in rootless containers, runs four allowlisted attack scenarios against them, shows the security events, and verifies (and tampers with copies of) the signed evidence through `aegis.verify_cli`. Without Podman it starts in a labelled degraded mode with a recorded replay. Guide: [`docs/prototype/PROTOTYPE_GUIDE.md`](docs/prototype/PROTOTYPE_GUIDE.md). Five-minute judge path: [`docs/prototype/JUDGE_WALKTHROUGH.md`](docs/prototype/JUDGE_WALKTHROUGH.md).

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
- **Timing side channel:** a simple classifier reads the defence's decision from response time with 0.795–0.800 accuracy unpadded; 250 ms response padding lowers it to 0.495–0.555, at +198 to +201 ms per answered request. This weakens one classifier; it does **not** show the channel is gone.
- **Real model — PRECOMPUTED from saved runs** (Qwen2.5-0.5B Q4_K_M, llama.cpp on CPU, loopback only): 0 / 104 sessions recovered another session's canary (1,040 trials); full pipeline 0 / 26 runs. The positive controls that are built to leak did leak (16 / 16 and 13 / 16 sessions), so the probes can detect a leak. Raw runs: `aegislab/evidence/phase3_2026-10-23/llm/`.

## Known limitations

Stated here because a security result is only as credible as its limits.

- **Trusted broker and signing key.** The broker sees everything and signs the checkpoints. A compromised broker or a stolen key can produce false but consistent records.
- **Global role tokens.** Tokens are per role, not per run, and are local demo tokens (`var/keys/tokens.json`). `AEGIS_DEMO_MODE=1` hands every token to any local caller: demo only. The prototype console refuses to start with it: it keeps the tokens on the server and gives the browser a loopback operator session instead (one local operator, not multi-user authentication).
- **One host.** Validated on a single Fedora machine. Containers share the host kernel; a kernel or runtime escape is out of scope.
- **Small model, few prompts.** One 0.5B model on CPU and ten probe wordings; three probes stayed silent even when sharing was on purpose. Zero observed leaks is not proof of zero risk (one-sided 95% upper bound: 2.84% of sessions for this setup).
- **Detector gaps.** The canary detector misses some re-encodings, for example **base64**.
- **Timing.** Padding weakens one measured classifier; other side channels (cache, memory bandwidth, scheduling, power) remain shared.
- **GPU and accelerator KV-cache isolation were not tested.** Only CPU inference was exercised. The proposed GPU boundary is described in `aegislab/README.md` ("GPU inference boundary").
- **Saved real-model results.** The judge and security demos show the real-model numbers from saved runs; they never run a model live. Re-running the experiments needs a local `llama-server` binary and a GGUF model file (not included, nothing is downloaded by the repo) and takes about 3.5 hours (`evaluation/llm_isolation.py`).
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
