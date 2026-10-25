# AegisLab: prototype build report

> **Phase 4 note (23 Oct 2026):** the deck, PDF, video, captions, voice-over, storyboard and Judge Q&A were regenerated in the Phase 4 candidate and no longer carry the figures below. Figures in this report are those of its own date; `README_FIRST.md` and `PHASE4_PRESENTATION_REPORT.md` describe the current package.


Team Tech Mavericks · Hack in Hills ’26 · Track 04 (Bayora) · report date 22 Oct 2026, one day before the prototype submission.

> **Update, 22 Oct 2026:** this report is kept as submitted. Where it says truncation is undetected (0/30) or compares timing at 0.80 vs 0.57, or says a CPU hog does not move round-trip time (22 Oct: an unrestricted CPU hog raises it by +37.5% to +51.7%, addendum section 4), or lists `quickstart.sh` as unrun, see `VALIDATION_ADDENDUM_2026-10-22.md` for what was fixed and re-measured afterwards (separate evidence folder `aegislab/evidence/validation_2026-10-22/`).

## 1. Status

The prototype is complete and runs. On 22 Oct 2026 we re-verified it on a clean checkout (new virtualenv, fresh `podman pull`):

| Check | Result |
|---|---|
| `pytest -q tests` | 13 passed in 2.8 s |
| `scripts/demo_run.py DEMO-001` | run reaches RELEASED |
| `GET /api/runs/DEMO-001/verify` | `ok: true`, 25 audit entries, 4 checkpoints checked, 0 findings |
| Web console served by the API | HTTP 200 on `/` |
| Full evaluation re-run (10 runs per condition, 105 s, in a scratch copy so the submitted numbers stay untouched) | Every security outcome reproduced exactly (see section 4). Only timings differ |

Re-run environment: Fedora, Podman 5.8.9 rootless, Python 3.14.8, RTX 4050 laptop (not used). Submitted results were measured on Podman 5.8.1.

## 2. What we built

### Control plane and sandbox (Python, 2,152 lines in total, including 130 test lines, the evaluation harness and scripts)

| Component | File | What it does |
|---|---|---|
| Runtime wrapper | `aegis/runtime.py` | Rootless Podman. `--network none`, read-only root, all capabilities dropped, non-root, `no-new-privileges`, cgroup CPU/memory/pid limits, private SELinux labels |
| Run lifecycle and broker | `aegis/runs.py` (520 lines) | `CREATED → FROZEN → RUNNING → SEALED → RELEASED`, or `FAILED` (fail-closed). Mailbox broker, identity bound to the channel, attack commitments, fresh model worker per run, 250 ms timing buckets, result gate |
| Audit | `aegis/audit.py`, `aegis/crypto.py` | Hash-chained log, Ed25519 signed checkpoints copied to a reviewer vault |
| Evidence | `aegis/evidence.py`, `aegis/verify_cli.py` | Evidence report (JSON and Markdown), standalone verifier, tamper tests on a copy |
| API | `aegis/api.py` | FastAPI, role-based access (operator, reviewer, blue, red, observer), redacted monitoring stream |
| In-sandbox code | `sandbox/*.py` | Red agent, defence runner (attests frozen config), model worker (stub with an emulated prompt cache), mailbox spool |
| Samples | `samples/` | Synthetic attack pack, sample defence config |

### Web console (vanilla JS, 650 lines)

Overview with architecture diagrams, dashboard with filters, run details with timeline, evidence report with download, role selector, live-API mode and a static snapshot mode. It uses the template's fonts, the mountain image and the DEMO-001 run.

### Evaluation harness

`evaluation/run_evaluation.py` (352 lines) runs nine experiments, E1 to E9, and writes `evidence/results.json` and `RESULTS.md`.

### Submission package

| Deliverable | Detail |
|---|---|
| Deck | 8 slides on the official template, speaker notes on every slide (`.pptx` and matching `.pdf`, 8 pages) |
| Pitch video | 120.000 s, 1920x1080, 30 fps, H.264 + AAC, local synthetic voiceover, original music and effects, burned-in captions |
| Supporting text | Voiceover script (238 words), timestamped storyboard, SRT captions, Judge Q&A |
| Visuals | 5 diagrams (SVG and PNG), 3 captures from the running prototype, 1 labelled concept illustration |
| Evidence | `DEMO-001` bundle that anyone can verify independently, `RESULTS.md`, `results.json` |

### Added today

- `aegislab/scripts/quickstart.sh`: venv, dependencies, image pull, tests, DEMO-001 and the console in one command. Not run end to end yet: it only chains steps that each passed individually today.

## 3. Requirement coverage (Track 04 evaluation objectives)

| Objective | Coverage | Evidence |
|---|---|---|
| 01 Isolate without breaking function | Implemented | ~4 ms median per broker hop (2.33 ms on the re-run), CPU hog does not move round-trip time |
| 02 Prevent leakage | Implemented | 150/150 forbidden requests denied, 90/90 network connects failed, 0 payload strings in 894 monitoring events |
| 03 Preserve auditability | Implemented | modify, delete, reorder, truncate, rehash each detected 30/30 |
| 04 Deployability | Implemented | Rootless Podman on stock Linux, no special hardware, `Containerfile` included |
| 05 LLM-native threats | Partly | Fresh worker per run and canary probe work (control leaks 9/10). The cache is emulated by a stub |
| 06 Quantify residual risk | Implemented | Threat model in the README, slide 6, Judge Q&A, plus the measured 0/30 truncation gap |

## 4. Measured results (n and outcome)

| ID | Test | Submitted run (15 Oct) | Re-run (22 Oct) |
|---|---|---|---|
| E1 | Config changes after freeze rejected | 5/5, edited file fails closed | same |
| E2 | Forbidden broker ops denied / connects failed / foreign paths absent | 150/150, 90/90, 90/90 | same |
| E3 | Broker round-trip median | 4.32 ms | 2.33 ms |
| E4 | Canary leaks, fresh worker / reused worker (control) | 0/20, 9/10 | same |
| E5 | Audit tamper detected (5 types) | 30/30 each, 0/30 with only the freeze checkpoint | same |
| E6 | Gate: early or wrong-role access refused; sealed runs released | all refused, 30/30 | same |
| E7 | Timing classifier accuracy, no padding / 250 ms buckets | 0.80 / 0.57 | 0.80 / 0.56 |
| E8 | Payload strings in monitoring output | 0 of 75 in 894 events | same |
| E9 | Round-trip with CPU hog | no change | no change |

The submitted `evidence/` folder still holds the 15 Oct numbers, since the deck, site and video quote them. The re-run copy is in the session scratchpad only.

## 5. Limits we state openly

- The model under test is a deterministic stub, not an LLM. No real KV-cache or GPU state was tested.
- Identities are local demo tokens. State is JSON files. Single host.
- No hosted URL: the site runs locally or as a static snapshot.
- Broker, host kernel, runtime and signing-key compromise are out of scope. Containers share the host kernel. Cache and memory-bandwidth side channels are not covered.
- A reviewer who keeps only the freeze checkpoint cannot detect truncation (measured 0/30).
- Zero leakage in finite tests is evidence for this configuration, not proof.
- Market, pricing and revenue figures on the deck are labelled assumptions. There are no customers or Bayora agreement.

## 6. How it stands

I cannot predict the judging outcome, so I will not give a score. What this has going for it: it is a working, tested proof of concept (not a mock-up), it reproduces on a second run, it maps one-to-one to the six stated objectives, and it states its residual risks with measured numbers. The weak points a judge may probe: the stub model, no public URL, single-host scope.

## 7. Open decisions

1. **Public URL.** Deploying the static snapshot (`aegislab/web`, actions disabled) to Vercel would give a live link. It publishes the site, so it needs your go-ahead, and the deck and `README_FIRST.md` would then need the URL added.
2. **Real model.** An optional inference client in place of `sandbox/model_worker.py` would answer the stub criticism. This machine has no model server installed (6 GB GPU, ~8 GB free RAM), so it needs a small model download first.
