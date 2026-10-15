# AegisLab prototype

Secure infrastructure for adversarial AI evaluation. Team Tech Mavericks, Hack in Hills ’26, Track 04 (Bayora).

**Status: implemented prototype.** It is a working single-host proof of concept with measured results. It is not a production security system. The model under test is a deterministic **stub**, not an LLM.

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
| Hash-chained audit log and Ed25519 checkpoints pushed to a reviewer vault | `aegis/audit.py` |
| Result gate: SEALED, audit verifies, commitments verify, reviewer identity | `aegis/runs.py` (`release`) |
| Redacted monitoring stream (no payloads, outputs or rules) | `monitor.jsonl`, `GET /api/runs/{id}/events` |
| Independent verifier and tamper tests | `aegis/verify_cli.py` |
| Web console: overview, dashboard, run details, evidence report | `web/` |

## Run it locally

Requirements: Linux with rootless Podman (tested: Fedora, kernel 6.19, Podman 5.8.1, crun 1.27, cgroups v2, SELinux enforcing), Python 3.11+.

```bash
cd aegislab
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
podman pull docker.io/library/python:3.12-slim

# 1. tests (13; the end-to-end one needs Podman)
pytest -q tests

# 2. create, freeze, run, seal and release the demo run
python scripts/demo_run.py DEMO-001

# 3. measured evaluation (about 2 minutes): writes evidence/results.json and evidence/RESULTS.md
python evaluation/run_evaluation.py --runs 10

# 4. web console with live API (local demo identities enabled)
AEGIS_DEMO_MODE=1 uvicorn aegis.api:app --host 127.0.0.1 --port 8400
# open http://127.0.0.1:8400
```

To try the gated actions, use the "Viewing as" selector: Operator (create/freeze/start), Reviewer (release, tamper test), Blue or Red participant (gets 403 before release). The API enforces these identities. They are local demo tokens in `var/keys/tokens.json`; production would use SSO/OIDC.

**Static mode (no backend):** `python -m http.server 8000 -d web` and open http://127.0.0.1:8000. The site then loads `web/snapshot/` (exported by `scripts/export_snapshot.py` from the local run) and says so in the top banner. Actions are disabled; tamper-test results there were computed by the local prototype.

**Independent verification of a run** (reviewer side). The submitted DEMO-001 bundle is in `evidence/DEMO-001/`:

```bash
python -m aegis.verify_cli --audit evidence/DEMO-001/audit.jsonl \
  --checkpoints evidence/DEMO-001/reviewer_checkpoints.jsonl \
  --pubkey "$(cat evidence/DEMO-001/broker_public_key.b64)" --sealed
# prints {"ok": true, "entries": 25, "checkpoints_checked": 4, ...}; edit any line of audit.jsonl and it fails
```

For runs you create yourself, the same files are in `var/runs/<id>/` and `var/reviewer_vault/<id>.jsonl`.

## API (127.0.0.1:8400)

| Method | Path | Who |
|---|---|---|
| GET | `/api/runs`, `/api/runs/{id}`, `/api/runs/{id}/events` | anyone (redacted) |
| POST | `/api/runs`, `/api/runs/{id}/freeze`, `/api/runs/{id}/start` | operator |
| POST | `/api/runs/{id}/defence-config` | blue participant / operator, CREATED only |
| POST | `/api/runs/{id}/release` | reviewer, SEALED only |
| GET | `/api/runs/{id}/artifacts` | participants / reviewer, RELEASED only |
| GET | `/api/runs/{id}/evidence`, `/evidence.md` | reviewer, or anyone after release |
| GET | `/api/runs/{id}/verify` | anyone |
| POST | `/api/runs/{id}/tamper-test` | reviewer / operator (works on a copy) |

Identity header: `X-Aegis-Token`.

## Threat model

**Assets:** attack payloads (red IP, must stay hidden from blue until release), defence configuration (blue IP, hidden from red), model state (must not carry over between runs), evaluation evidence (must be independently checkable).

**Adversaries:** a malicious or curious red workload, blue workload, or participant; a later run trying to read an earlier run; someone editing the audit log after the fact.

**Trusted computing base:** host kernel, Podman/crun, the broker/control-plane process, the Ed25519 signing key, and the authorised reviewer who retains checkpoints.

**Assumptions:** the host is not compromised; the reviewer keeps the seal and release checkpoints outside the run store; participants cannot run code on the host.

### What it protects against (tested, see `evidence/RESULTS.md`)

- Red reading blue's config, verdicts or release endpoint through the broker; spoofing the blue identity; running uncommitted or replayed payloads.
- Network access from any sandbox (no interfaces except loopback).
- Changing the defence configuration after freeze (API rejects; a modified frozen file makes the defence runner's attestation fail and the run fails closed).
- Cross-run carry-over through a reused model worker (fresh container per run; canary probe detects reuse in the control experiment).
- Editing, deleting, reordering or rehashing audit entries, and truncation up to the last checkpoint the reviewer holds.
- Blue or red participants reading artifacts before release; release before seal or by a non-reviewer.

### What it does not protect against, and when guarantees fail

- **Broker, host kernel, runtime or signing-key compromise.** The broker sees everything and signs checkpoints; a compromised broker can read sealed artifacts and write false entries before signing. A hash chain cannot detect lies told at write time.
- **Kernel or container-runtime escape.** Containers share the host kernel. MicroVMs (Kata, Firecracker) or gVisor are the next step.
- **Shared-hardware side channels.** Last-level cache, memory bandwidth, scheduling and power remain shared. CPU quotas apply; per-tenant cpusets were *not* applied on the test host because the cpuset controller is not delegated to rootless users.
- **Defence inference through authorised outputs.** Red legitimately sees refusals. Uniform refusals and timing buckets reduced a simple timing classifier from 0.80 to 0.57 accuracy (0.50 = chance). Reduced, not removed.
- **Model cache and cleanup on real inference servers.** Only the stub was tested. GPU KV-cache, CUDA contexts and prefix caching need their own boundary.
- **Monitoring metadata.** Content is redacted, but event timing and counts are visible.
- **Audit truncation without retained checkpoints.** If the reviewer keeps only the freeze checkpoint, later entries can be dropped undetected (measured: 0/30 detected).
- **Finite testing.** No leakage in these tests is evidence for this configuration, not proof of confidentiality.

### GPU inference boundary (proposed, not implemented)

CPU tooling isolation (these containers) is separate from GPU inference isolation. A real model server should run behind its own boundary, with prefix/KV caching disabled across tenants, a process restart or verified cache flush per run, and the canary probe kept as the verification step.

## Design choices

- **Mailbox instead of sockets or networks.** Tenants keep `--network none`. On this SELinux host, container processes may not `connectto` a host Unix socket, and disabling labels would weaken isolation. Files in a per-container `:Z` volume work with SELinux enforcing. Cost: about 4 ms per broker hop (measured).
- **JSON files instead of a database.** Enough for the MVP; SQLite or PostgreSQL is proposed.
- **Stub model.** Makes leakage and jailbreak behaviour deterministic and testable. Replace `sandbox/model_worker.py` with an inference client to test a real model.

## Layout

```
aegis/        control plane: api.py, runs.py (lifecycle, broker, gate), audit.py, crypto.py, runtime.py, evidence.py, verify_cli.py
sandbox/      code that runs inside containers (standard library only)
samples/      synthetic attack pack and sample defence configuration
web/          web console (vanilla JS); web/snapshot = static export
tests/        pytest suite
evaluation/   measured evaluation harness
evidence/     results.json, RESULTS.md from the evaluation run
scripts/      demo_run.py, export_snapshot.py
var/          runtime state (created on first run; contains demo keys, not committed)
```

## Licences

Code: written for this hackathon by Team Tech Mavericks. Fonts in `web/fonts`: Montserrat, IBM Plex Sans and IBM Plex Mono, SIL Open Font License 1.1. Mountain photograph: from the official Hack in Hills ’26 presentation template. Python dependencies: FastAPI (MIT), Uvicorn (BSD-3), cryptography (Apache-2.0/BSD).
