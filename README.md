# AegisLab prototype

Secure infrastructure for adversarial AI evaluation. Team Tech Mavericks, Hack in Hills ’26, Track 04 (Bayora).

**Status: implemented prototype.** It is a working single-host proof of concept with measured results. It is not a production security system. By default the model under test is a deterministic **stub**, not an LLM; an optional, opt-in OpenAI-compatible adapter exists (see "Optional real-model backend").

**Two result sets exist and are kept apart.** The 15 Oct 2026 submission numbers are in `evidence/results.json`, `evidence/RESULTS.md` and `evidence/DEMO-001/` and are unchanged. The 22 Oct 2026 hardening validation (terminal audit anchor, access matrix, real-model experiments, held-out timing analysis) is in `evidence/validation_2026-10-22/`, summarised in `../VALIDATION_ADDENDUM_2026-10-22.md`; the timing figures there were superseded by the Phase 1 closeout executions in `evidence/closeout_2026-10-22/`. The full threat table with measured results and residual risk is `THREAT_MODEL.md`.

## What it does

A run puts three workloads side by side: a **red sandbox** (attack agent), a **blue defence runner** (an isolated workload that applies the frozen defence configuration) and a **model worker**. None of them has a network. The only channel each one has is a private mailbox directory that the **trusted broker** on the host reads and writes.

Lifecycle: `CREATED → FROZEN → RUNNING → SEALED → RELEASED` (or `FAILED`, fail-closed).

| Mechanism | Where |
|---|---|
| No-network, read-only, capability-free, non-root sandboxes with cgroup limits and private SELinux labels | `aegis/runtime.py` |
| Mailbox IPC, no symlink following, 64 KiB message cap | `sandbox/spool.py`, `aegis/runs.py` (`_safe_read`) |
| Identity bound to the mailbox, not to a claimed field | `aegis/runs.py` (`Broker.attack`) |
| Frozen config: manifest digests and defence-runner attestation | `aegis/runs.py` (`freeze`), `sandbox/defence_runner.py` |
| Attack commitments `SHA-256(nonce ‖ 0x00 ‖ payload)`, 128-bit nonce | `sandbox/red_agent.py`, `aegis/crypto.py` |
| Fresh model worker container per run; canary plant and probe | `aegis/runs.py`, `samples/attack_pack.json` |
| Timing buckets: red only gets answers on 250 ms boundaries | `aegis/runs.py` (`Broker.attack`) |
| Hash-chained audit log; chained Ed25519 checkpoints; signed **terminal checkpoint** (run id, final state, final seq/hash, event count, previous checkpoint) in the reviewer vault and a separate anchor store; fail-closed verifier | `aegis/audit.py`, `aegis/runs.py`, `aegis/store.py` |
| Optional real-model adapter (stateless requests, loopback only, key never logged); stub stays default | `aegis/model_client.py` |
| Result gate: SEALED, audit verifies, commitments verify, reviewer identity | `aegis/runs.py` (`release`) |
| Redacted monitoring stream (no payloads, outputs or rules) | `monitor.jsonl`, `GET /api/runs/{id}/events` |
| Independent verifier (`--bundle`, `--anchor`, `--expect-state`, `--expect-events`) and 12 tamper modes | `aegis/verify_cli.py` |
| Web console: overview, dashboard, run details, evidence report | `web/` |

## Run it locally

Requirements: Linux with rootless Podman (tested: Fedora, kernel 7.2, Podman 5.8.9, crun 1.28, cgroups v2, SELinux enforcing; the 15 Oct numbers were measured on kernel 6.19 / Podman 5.8.1), Python 3.11+ (tested 3.14), network access to PyPI and, the first time, to Docker Hub for `python:3.12-slim`.

**One command** (venv, dependencies, sandbox image, tests, DEMO-001, independent verification, with a PASS/FAIL line per stage; nonzero exit if any security test fails):

```bash
cd aegislab
scripts/quickstart.sh            # add --serve to run the console in the foreground (Ctrl-C stops it)
```

State goes to `var/quickstart/` (never to `evidence/` or `var/DEMO-001`). Re-running reuses a completed DEMO-001; delete `var/quickstart` to start over. The script creates only a project-local `.venv`, never installs globally, and never stops containers it did not start. Prerequisite failures (no Podman, not rootless, old Python, no network) print the stage, the cause and what to do.

Step by step:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
podman pull docker.io/library/python:3.12-slim

pytest -q tests                                   # 144 tests; includes the security regression suites and one Podman end-to-end run
AEGIS_VAR=var/mine python scripts/demo_run.py DEMO-001 --bundle-dir var/mine/bundles/DEMO-001
python -m aegis.verify_cli --bundle var/mine/bundles/DEMO-001
scripts/security_demo.sh                          # judge-facing demonstration (a few seconds once the image is built), fresh temp state, exits 0 only if every check behaves
AEGIS_VAR=var/mine AEGIS_DEMO_MODE=1 uvicorn aegis.api:app --host 127.0.0.1 --port 8400   # console
```

Evaluations (each writes only to the `--out` folder; the runner refuses to write into `evidence/` itself):

```bash
AEGIS_VAR=var/scratch python evaluation/run_evaluation.py --runs 10 --out evidence/validation_<date>/e1_e9_rerun     # original E1-E9 harness, ~2 min
AEGIS_VAR=var/scratch python evaluation/run_validation.py --out evidence/validation_<date> --runs 30                 # audit tamper/truncation x30 + access matrix, ~3 min
AEGIS_VAR=var/scratch python evaluation/timing_eval.py --runs 20 --out evidence/validation_<date>/timing.json         # held-out timing analysis + RTT, ~9 min (summaries only)
AEGIS_VAR=var/scratch python evaluation/timing_closeout.py --seed 1 --out-dir evidence/closeout_<date>/timing/exec1     # one execution with run id, source hashes and raw per-request / per-round-trip files, ~8 min
python evaluation/timing_aggregate.py --out evidence/closeout_<date>/timing/aggregate.json evidence/closeout_<date>/timing/exec*   # combine executions, held-out transfer, verdicts
```

To try the gated actions, use the "Viewing as" selector: Operator (create/freeze/start), Reviewer (release, tamper test), Blue or Red participant (gets 403 before release). The API enforces these identities. They are local demo tokens in `var/keys/tokens.json`; production would use SSO/OIDC. `AEGIS_DEMO_MODE=1` makes `GET /api/demo/identities` hand out every token to any local caller: demo only.

**Static mode (no backend):** `python -m http.server 8000 -d web` and open http://127.0.0.1:8000. The site then loads `web/snapshot/` (exported by `scripts/export_snapshot.py` from the 15 Oct run) and says so in the top banner. Actions are disabled; tamper-test results there were computed by the local prototype at that time.

### Independent verification of a run (reviewer side)

A reviewer keeps three things off the host at release time: the exported bundle (`audit.jsonl`, `reviewer_checkpoints.jsonl`, `terminal_anchor.json`), and the broker public key pinned out of band (compare `signing_key_id`). Then:

```bash
python -m aegis.verify_cli --bundle <dir>          # exit 0 = valid AND complete; exit 1 = anything else
python -m aegis.verify_cli --audit audit.jsonl --checkpoints vault.jsonl --pubkey <base64> \
    --anchor terminal_anchor.json --run-id DEMO-001 --expect-state RELEASED --expect-events 25
```

The verifier is **fail-closed**: a log with no signed terminal checkpoint (or retained anchor) is never reported valid, because a truncated log cannot show that it was truncated. `--allow-in-progress` is the explicit opt-out for unfinished runs and old bundles; it exits 0 only with a stderr warning that completeness is not established.

A published example is in `evidence/validation_2026-10-22/bundles/`: `VAL-001` must verify and `VAL-001_TAMPERED_truncated_last3` must fail. A completed, released `DEMO-001` that passes strict verification is in `evidence/closeout_2026-10-22/DEMO-001_released/` (`python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released`, exit 0). The **submitted** `evidence/DEMO-001/` bundle is the completed 15 Oct run in the legacy format; it has no terminal checkpoint, so strict verification rejects it ("no signed terminal checkpoint ... legacy checkpoints only"). `--allow-in-progress` checks chain and checkpoint consistency only (`ok: true, terminal_verified: false`) and is **not** equivalent to verifying a completed run. The legacy bundle is intentionally left unchanged.

### Optional real-model backend

Off by default. The stub keeps running unless you opt in:

```bash
export AEGIS_MODEL_BACKEND=openai_compatible
export AEGIS_MODEL_BASE_URL=http://127.0.0.1:8081/v1     # loopback only unless AEGIS_MODEL_ALLOW_REMOTE=1
export AEGIS_MODEL_NAME=<model id>
export AEGIS_MODEL_API_KEY_FILE=/path/to/keyfile          # mode 0600; or AEGIS_MODEL_API_KEY
```

The setting is recorded in the frozen manifest (never the key); changing it after freeze fails the run. Requests are stateless (one message, no history or session id), proxies and redirects are ignored, an unreachable server fails the run closed (no fallback to the stub), and three consecutive errors abort. AegisLab cannot clear state inside the inference server. `evaluation/model_experiments.py` measures what it can (needs a local llama.cpp `llama-server` binary and a GGUF file; nothing is downloaded by the repo). Details and limits: `THREAT_MODEL.md` rows 4 and 10.

## API (127.0.0.1:8400)

| Method | Path | Who |
|---|---|---|
| GET | `/api/runs`, `/api/runs/{id}`, `/api/runs/{id}/events` | anyone (redacted; blue-config and attack-pack digests only for operator/reviewer until release) |
| POST | `/api/runs`, `/api/runs/{id}/freeze`, `/api/runs/{id}/start` | operator |
| POST | `/api/runs/{id}/defence-config` | blue participant / operator, CREATED only |
| POST | `/api/runs/{id}/release` | reviewer, SEALED only |
| GET | `/api/runs/{id}/artifacts` | participants / reviewer, RELEASED only |
| GET | `/api/runs/{id}/evidence`, `/evidence.md` | reviewer, or anyone after release (header token only; `?token=` was removed) |
| GET | `/api/runs/{id}/verify` | anyone |
| POST | `/api/runs/{id}/tamper-test` | reviewer / operator (works on a copy) |

Identity header: `X-Aegis-Token`.

## Threat model

**Assets:** attack payloads (red IP, must stay hidden from blue until release), defence configuration (blue IP, hidden from red), model state (must not carry over between runs), evaluation evidence (must be independently checkable).

**Adversaries:** a malicious or curious red workload, blue workload, or participant; a later run trying to read an earlier run; someone editing the audit log after the fact.

**Trusted computing base:** host kernel, Podman/crun, the broker/control-plane process, the Ed25519 signing key, and the authorised reviewer who retains checkpoints.

**Assumptions:** the host is not compromised; the reviewer keeps the vault copy or the terminal anchor outside the run store and pins the broker public key out of band (see `THREAT_MODEL.md`, section 2); participants cannot run code on the host.

### What it protects against (tested, see `evidence/RESULTS.md` and `evidence/validation_2026-10-22/`)

- Red reading blue's config, verdicts or release endpoint through the broker; spoofing the blue identity; running uncommitted or replayed payloads.
- Network access from any sandbox (no interfaces except loopback).
- Changing the defence configuration after freeze (API rejects; a modified frozen file makes the defence runner's attestation fail and the run fails closed).
- Cross-run carry-over through a reused model worker (fresh container per run; canary probe detects reuse in the control experiment).
- Editing, deleting, reordering, duplicating or rehashing audit entries; removing, reordering or swapping checkpoints; truncating the tail (including when the reviewer kept only an early checkpoint, as long as the terminal anchor or the full vault copy survives); checkpoints or anchors from another run; a terminal state that disagrees with the recorded lifecycle state.
- Blue or red participants reading artifacts before release; release before seal or by a non-reviewer.

### What it does not protect against, and when guarantees fail

- **Broker, host kernel, runtime or signing-key compromise.** The broker sees everything and signs checkpoints; a compromised broker can read sealed artifacts and write false entries before signing. A hash chain cannot detect lies told at write time.
- **Kernel or container-runtime escape.** Containers share the host kernel. MicroVMs (Kata, Firecracker) or gVisor are the next step.
- **Shared-hardware side channels.** Last-level cache, memory bandwidth, scheduling and power remain shared. CPU quotas apply; per-tenant cpusets were *not* applied on the test host because the cpuset controller is not delegated to rootless users.
- **Defence inference through authorised outputs.** Red legitimately sees refusals. On the 15 Oct in-sample measure, 250 ms buckets reduced a simple classifier from 0.80 to 0.57. The 22 Oct held-out analysis (three complete executions, n=200 per setting each, raw data kept in `evidence/closeout_2026-10-22/timing/`) found: no padding 0.795–0.800 (p=0.001 each), 100 ms 0.510–0.545, 250 ms 0.495–0.555, 500 ms 0.495–0.510, none significantly above chance (smallest p 0.136); 250 ms adds +198 to +201 ms to answered requests. Not distinguishable from chance at this n is not proof of absence.
- **Model cache and cleanup on real inference servers.** Only the stub was tested. GPU KV-cache, CUDA contexts and prefix caching need their own boundary.
- **Monitoring metadata.** Content is redacted, but event timing and counts are visible.
- **Audit: what still defeats it.** The 15 Oct gap (reviewer keeps only the freeze checkpoint: 0/30 detected) is closed by the terminal checkpoint and the fail-closed verifier (30/30). Still undetected: an attacker who holds the signing key and replaces every retained copy (vault, anchor store, exported bundle); a compromised verifier or pinned key; a broker that signs false entries.
- **Finite testing.** No leakage in these tests is evidence for this configuration, not proof of confidentiality.

### GPU inference boundary (proposed, not implemented)

CPU tooling isolation (these containers) is separate from GPU inference isolation. A real model server should run behind its own boundary, with prefix/KV caching disabled across tenants, a process restart or verified cache flush per run, and the canary probe kept as the verification step.

## Design choices

- **Terminal anchor instead of "more checkpoints".** Truncation cannot be shown by the log itself. The broker signs one terminal checkpoint when a run reaches RELEASED or FAILED, the chain is closed atomically with the final event (later events go to an unsigned `post_terminal.jsonl`), and verification requires that checkpoint. Where the vault and anchor store live decides how strong this is: `AEGIS_VAULT` / `AEGIS_ANCHORS` can point at storage the run-directory writer cannot reach.

- **Mailbox instead of sockets or networks.** Tenants keep `--network none`. On this SELinux host, container processes may not `connectto` a host Unix socket, and disabling labels would weaken isolation. Files in a per-container `:Z` volume work with SELinux enforcing. Cost: about 4 ms per broker hop (measured).
- **JSON files instead of a database.** Enough for the MVP; SQLite or PostgreSQL is proposed.
- **Stub model.** Makes leakage and jailbreak behaviour deterministic and testable; it stays the default. The optional adapter (`aegis/model_client.py`) calls a real endpoint from the broker, not from a sandbox, because the sandboxes have no network.

## Layout

```
aegis/        control plane: api.py, runs.py (lifecycle, broker, gate), audit.py, crypto.py, runtime.py, evidence.py, verify_cli.py
sandbox/      code that runs inside containers (standard library only)
samples/      synthetic attack pack and sample defence configuration
web/          web console (vanilla JS); web/snapshot = static export
tests/        pytest suite (test_core, test_audit_integrity, test_isolation, test_model_client)
evaluation/   run_evaluation.py (E1-E9), run_validation.py, isolation_matrix.py, timing_eval.py, model_experiments.py
evidence/     15 Oct results (results.json, RESULTS.md, DEMO-001/) and validation_2026-10-22/ (new, separate)
scripts/      quickstart.sh, security_demo.sh/.py, demo_run.py, export_snapshot.py
THREAT_MODEL.md  threat table, trust model, residual risk
var/          runtime state (created on first run; contains demo keys, not committed)
```

## Licences

Code: written for this hackathon by Team Tech Mavericks. Fonts in `web/fonts`: Montserrat, IBM Plex Sans and IBM Plex Mono, SIL Open Font License 1.1. Mountain photograph: from the official Hack in Hills ’26 presentation template. Python dependencies: FastAPI (MIT), Uvicorn (BSD-3), cryptography (Apache-2.0/BSD).
