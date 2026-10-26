# Phase R1 report: functional prototype console

**Team:** Tech Mavericks.
**Event:** Hack in Hills '26, Track 04.
**Date:** 26 Oct 2026.
**Branch:** `r1/functional-prototype`.
**Base:** `f1e28552c2b65c44ebb73351e889053fc1d15c09` (main, R0).

Phase R1 adds an interactive, judge-ready web prototype to AegisLab. It is a browser console on top of the existing FastAPI control plane. The broker, sandbox hardening, result gate, audit log and verifier are reused unchanged. The new code is one Python module, `aegis/console.py`, which adds a bounded `/api/lab/...` adapter. Alongside it are a static front end, a launcher and a test file.

## 1. Discovered architecture (what already existed)

| Component | File | Role used by the console |
|---|---|---|
| Control plane API | `aegis/api.py` | Every `/api/...` route, the role tokens (`X-Aegis-Token`, constant-time check in `role_of`/`need`), and the demo identity endpoint (only with `AEGIS_DEMO_MODE=1`) |
| Run lifecycle, broker, result gate | `aegis/runs.py` | CREATED, FROZEN, RUNNING, SEALED, then RELEASED or FAILED. Mailbox broker with commitments, canary withholding and timing buckets. `release()` verifies the chain and the commitments before release. `verify_run()` |
| Audit | `aegis/audit.py`, `aegis/crypto.py` | Hash-chained `audit.jsonl`; Ed25519 v2 chained checkpoints in the reviewer vault; terminal checkpoint and anchor store |
| Sandbox runtime | `aegis/runtime.py` | `hardening_flags(role)`: `--network none`, `--read-only`, `--cap-drop ALL`, no-new-privileges, `--userns keep-id`, pids, memory and CPU limits; rootless Podman |
| Verifier | `aegis/verify_cli.py` | Independent, fail-closed bundle verifier (`--pubkey`, `--expect-terminal-hash`); `TAMPER_MODES` (12 in-memory modes) behind `POST /api/runs/{id}/tamper-test` |
| Evidence export | `aegis/evidence.py` | `export_bundle(run_id, dir)` |
| Claim checkers | `evaluation/check_claims.py` | `phase3_rows()` (48 checks) and `timing_rows()` (72 checks) recompute quoted figures from raw files |
| Legacy web UI | `web/index.html`, `web/app.js`, `web/snapshot/` | A static 15 Oct console, left untouched |

**Constraint found during inspection.** The Phase 3 evidence pins the SHA-256 of these files:

- `aegis/api.py`, `aegis/evidence.py`, `aegis/model_client.py`, `aegis/runs.py`;
- `evaluation/llm_common.py`, `evaluation/llm_isolation.py`;
- `samples/*.json`;
- `sandbox/defence_runner.py`, `sandbox/red_agent.py`.

`MANIFEST.sha256` pins 442 release files, including `aegislab/README.md`. Editing any of these would break `check_claims` (48 Phase 3 checks) and judge-demo step 6. **None of them was modified.** The console wraps them instead.

## 2. What changed

The changes are additive: no tracked file under `aegislab/` was modified. Outside `aegislab/`, the root `README.md` was edited; it is not covered by the manifest.

- `aegis/console.py` (new): an outer FastAPI app.
  - A request guard: loopback Host only, a 256 KiB body cap, and security headers.
  - The lab API, described in section 5.
  - Static serving of `web/console/`.
  - It mounts `aegis.api.app` unchanged at `/`.
- `web/console/index.html`, `console.css`, `console.js` (new): seven pages.
  - Overview.
  - Isolation topology.
  - Attack lab, with a live run, four scenarios, a free probe and replay.
  - Security events.
  - Evidence verification.
  - Experiment results.
  - Threat model and limits.
  - The fonts are reused from the legacy `web/fonts/`.
- `scripts/start_prototype.sh` (new): the launcher (section 7).
- `tests/test_r1_console.py` (new): 41 tests (section 9).
- `docs/prototype/` (new):
  - this report;
  - `PROTOTYPE_GUIDE.md`;
  - `JUDGE_WALKTHROUGH.md`;
  - six screenshots taken from the running app.
- `README.md` (root): a short "Interactive prototype console" section and three layout lines.

## 3. Integration

```
browser ──HTTP (127.0.0.1)──> aegis.console:app
                               ├─ guard middleware (Host allowlist, body cap, CSP and headers)
                               ├─ /api/lab/...          new bounded adapter
                               │     └─ calls aegis.api.app in-process (TestClient on loopback) with the real role tokens
                               │        and calls runs.verify_run / evidence.export_bundle / runtime.hardening_flags
                               │     └─ runs python -m aegis.verify_cli as a subprocess for bundle verification
                               ├─ /console/...          static front end
                               └─ / (mount)             aegis.api.app, unchanged: /api/runs/..., /api/demo/identities, legacy site
```

- **Scenarios use the real handlers.** Each scenario sends real HTTP requests to the unchanged control plane, through the same role checks and gates. It then checks the outcome from the system's own state: HTTP status, run state, the new audit entry found by type and op after the pre-call sequence number, and the absence of protected values in the response bodies.
- **The probe uses real code paths.** The containment probe uses the red sandbox's real `hardening_flags("red")` and `Broker._spool_mounts`. It replies through the broker's real `runs._write_msg`.
- **Evidence uses the real verifier.** The evidence centre calls the real verifier program, never a reimplementation.

## 4. Security decisions

| Decision | Reason |
|---|---|
| Bind 127.0.0.1 only; refuse a non-loopback `Host` with 421 (`AEGIS_CONSOLE_HOSTS` overrides) | The browser receives all four demo tokens, so the console is a privileged local controller. The Host check stops DNS rebinding from making a web page a same-origin caller |
| Demo identities stay behind the existing `AEGIS_DEMO_MODE=1` switch | Reuses the existing gate; it is not a new mock. Without the flag, `/api/demo/identities` is 404 (tested) |
| State-changing lab endpoints need a real role token: operator for runs and scenarios, reviewer or operator for tamper | The existing `api.need` decides; the lab never assumes a role |
| No free-form input: scenario ids, bundle ids and tamper modes are dict keys; run ids match `LAB-\d{3}` and must exist; Pydantic `extra="forbid"`; `timing_bucket_ms` is 0 or 250 | Nothing from the browser reaches a shell, path, container option, image or network target |
| One state-changing lab action at a time (non-blocking lock gives 409); at most 2 verifier processes (429); at most 40 lab runs; one RUNNING run | Bounded resource use; no queueing of privileged work |
| Verifier subprocess timeout 30 s; probe container timeout 90 s, with forced `podman rm` on timeout | Fail closed rather than hang |
| Tamper only on a fresh temp copy of allowlisted regular files under `$AEGIS_VAR/lab`. The original's SHA-256 digests are compared before and after, and the copy is deleted in `finally` | The original evidence is never written (tested for all 7 modes) |
| Download only genuine bundles; zip only allowlisted regular files, no symlinks | No path traversal; tampered examples are not redistributed as if genuine |
| CSP `default-src 'self'`, no inline script, `frame-ancestors 'none'`; nosniff, no-referrer, X-Frame-Options DENY, no-store | Limits XSS and clickjacking; server strings are HTML-escaped (`esc`) or set with `textContent`; unescaped interpolations are numbers, booleans or constants |
| The API docs (`/docs`, `/redoc`, `/openapi.json`) of the mounted app are not served by the console | Smaller surface; the docs page would load scripts from a CDN |
| State in `var/console` (`AEGIS_VAR`), separate from the `var/` of quickstart | Never touches historical evidence or the quickstart's runs |
| The launcher unsets `AEGIS_MODEL_*` | The console always uses the stub; real-model results are shown as precomputed only, with no expensive reruns |
| Lab journal (`$AEGIS_VAR/lab/journal.jsonl`) is unsigned and labelled so | It is a UI convenience, not evidence; the audit log stays the record |

**Trust model:** unchanged.

- The broker, control plane and verifier host are trusted.
- Isolation is process, container, user-namespace and network isolation on one shared kernel. The topology page says so.

## 5. Endpoints (new, all under the console app)

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /` | none | Console page |
| `GET /api/lab/status` | none | Mode (live or degraded and why), Podman, model, hardening flags, runs, integrity of the latest terminal run, verifier result for the shipped DEMO-001, code revision |
| `POST /api/lab/runs` `{timing_bucket_ms}` | operator | Create, freeze and start `LAB-nnn` through the real API |
| `GET /api/lab/scenarios` | none | Scenario catalogue |
| `POST /api/lab/scenarios/{sid}/run` `{run_id}` | operator | Run one of `prohibited-access`, `cross-role-isolation`, `authorized-release`, `sandbox-containment` |
| `GET /api/lab/journal` | none | Last 50 lab actions (unsigned) |
| `GET /api/lab/timeline?run_id&limit` | none | Merged redacted monitoring stream (the same public data as `/api/runs/{id}/events`) |
| `GET /api/lab/bundles` | none | Bundle registry: 4 shipped, plus released lab runs |
| `POST /api/lab/bundles/{bid}/verify` | none | Run `aegis.verify_cli` (read-only) |
| `POST /api/lab/bundles/{bid}/tamper` `{mode}` | reviewer or operator | Tamper a disposable copy and verify both copies |
| `GET /api/lab/bundles/{bid}/download` | none | Zip of a genuine bundle plus `VERIFY.txt` |
| `GET /api/lab/tamper-modes` | none | The 7 disk-copy modes and the 12 in-memory modes |
| `GET /api/lab/experiments` | none | Precomputed results with a live recomputation through `check_claims` |
| `GET /api/lab/replay` | none | Recorded judge-demo transcript, labelled RECORDED EXECUTION |

Existing endpoints used unchanged:

- `/api/health`;
- `/api/runs[...]`, including `/freeze`, `/start`, `/release`, `/artifacts`, `/evidence`, `/events`, `/verify` and `/tamper-test`;
- `/api/demo/identities`.

## 6. Runtime modes and result labels

- **LIVE.** Rootless Podman is present and the sandbox image exists. Runs and the containment probe execute in real containers with the stub model.
- **DEGRADED.** Podman is missing, not rootless, or the image is missing. `POST /api/lab/runs` and the containment probe return 503 with the reason. The Attack lab shows the recorded 23 Oct judge-demo transcript (17/17), labelled **RECORDED EXECUTION (not live)**. Evidence verification and experiments work.

Labels shown in the UI:

- **LIVE SYSTEM TEST**: executed now.
- **RECORDED EXECUTION**: a saved transcript.
- **PRECOMPUTED REAL-MODEL EVIDENCE**: Phase 3 saved runs with Qwen2.5-0.5B.
- **STUB-MODEL TEST**: the deterministic stub.

The experiments page states that zero observed leaks bound a rate and do not prove isolation, and that GPU and accelerator KV-cache isolation were not tested.

## 7. Startup

```bash
cd aegislab
bash scripts/start_prototype.sh            # --port N, --check, --reset, --help
# open http://127.0.0.1:8400
```

The launcher:

- checks Python 3.11 or newer and the `.venv` (installing `requirements.txt` if needed);
- checks rootless Podman and builds the sandbox image if missing;
- checks the port is free;
- prints LIVE or DEGRADED;
- runs uvicorn on 127.0.0.1 with `AEGIS_VAR=var/console` and `AEGIS_DEMO_MODE=1`.

On exit, it removes only containers labelled `aegislab=1` whose names match the lab patterns.

## 8. Scenarios

| Scenario | Actors | Checks for PASS |
|---|---|---|
| Prohibited access | red GET artifacts, red POST release, anonymous GET artifacts | 3 × 403, each with its `policy.denied` audit entry (op read_artifacts, release, read_artifacts); state still SEALED; 0 protected markers in the bodies (canary, attack payloads, model outputs, the 4 tokens, `-----BEGIN`) |
| Cross-role isolation | blue GET artifacts; blue GET run; reviewer GET run; forged token GET evidence | 403 with audit, 200, 200, 401; secret digests absent for blue and present for the reviewer; exactly 5 broker `policy.denied` events from the red sandbox's own forbidden mailbox requests; 0 markers |
| Authorised release | reviewer POST release, reviewer GET artifacts | 200 with `run.released` by the reviewer; state RELEASED; `verify_run` ok with the terminal checkpoint verified; commitments verified equal revealed; bundle exported to `$AEGIS_VAR/bundles/LAB-nnn` |
| Sandbox containment | probe container with `hardening_flags("red")` and the real spool mounts | TCP to 1.1.1.1:53, 10.0.2.2:8400 and 127.0.0.1:8400, and DNS, all refused; rootfs write refused; foreign paths absent; CapEff 0; NoNewPrivs 1; Seccomp 2; uid ≠ 0; broker replies delivered as regular files despite the planted symlink and FIFO; victim file intact; broker writes under 2 s |

The verdict is PASS only if every step and every check holds. Any 5xx gives ERROR, never PASS.

The **Try a request yourself** panel sends one request from a fixed list of operations straight to the existing API with a chosen role token. It shows the raw status and decision.

## 9. Test results

All commands were run on 26 Oct 2026 on the Fedora test host (Python 3.14.8, Podman 5.8.9 rootless). Logs are in the session scratchpad, not in the repository.

| Command (from `aegislab/` unless noted) | Result | Exit |
|---|---|---|
| `pytest -q tests` (baseline at f1e2855, before changes) | 345 passed | 0 |
| `pytest -q tests/test_r1_console.py -m "not podman"` | 39 passed | 0 |
| `pytest -q tests/test_r1_console.py -m podman` | 2 passed (live run with all scenarios; containment probe) | 0 |
| `pytest -q tests` (after changes) | **386 passed** (345 existing + 41 new); no existing test changed or removed | 0 |
| `bash scripts/judge_demo.sh` | 17/17 checks behaved as expected | 0 |
| `bash scripts/security_demo.sh` | 34/34 checks, plus 1 documented limit shown (not counted) | 0 |
| `python evaluation/check_claims.py` | 14/14 quoted numbers, 72/72 timing, 48/48 Phase 3 (134 checks) | 0 |
| `python evaluation/check_presentation.py` | 157/157 | 0 |
| `sha256sum -c --quiet MANIFEST.sha256` (repo root) | 442 files OK | 0 |
| `python tools/publication_scan.py --repo .` (repo root, after staging the new files) | 0 FAIL, 0 WARN | 0 |

The Phase 3 source hashes show no drift: `check_claims` 48/48 includes the source-file hash checks, and `git diff` shows no tracked file under `aegislab/` modified.

**Browser verification.** The running app was checked in the in-app Chromium pane, at desktop width and at 375 px:

- all seven pages render;
- no horizontal page scroll at 375 px, after the fixes in this phase;
- live run, all four scenarios PASS, the release two-step confirmation, the free probe, event filters, verify (shipped and lab bundles), tamper PASS and the 12-mode in-memory suite all work.

The screenshots in `docs/prototype/screenshots/` come from that session.

New tests by group:

- request guard and pages: index with CSP; non-loopback Host gives 421 (4 hosts × 4 paths); loopback names accepted; 413 and 400 bodies; control plane mounted; demo identities off without the flag; API docs not served;
- status and modes: degraded mode fails closed (503) with the replay available; shipped-bundle integrity in status;
- authorisation and validation: operator-only runs and scenarios; 401 and 403; 422 on extra fields; allowlisted ids; lock busy gives 409;
- scenarios on a SEALED run produced by the real broker logic: prohibited, isolation, and release with lab-bundle verification and tamper; no tokens or key material in any lab response;
- timeline: merging, ordering, filter and 404;
- evidence: the 4 shipped bundles verify as expected; unknown ids rejected; 7 tamper modes PASS with the original byte-identical and the copy deleted; tamper auth and mode validation; download allowlist;
- experiments: figures equal to `check_claims` output;
- Podman: the full live flow and the containment probe.

## 10. Known issues and limits

- **Demo tokens.** The browser holds all four role tokens (demo mode). Anyone who can reach the port can act as any role. Mitigations: loopback bind, Host allowlist, no CORS, CSP. It must not be exposed on a network. Per-user login is out of scope.
- **Single process.** The lab lock and verifier semaphore are per process. The launcher runs one uvicorn worker; running several workers would weaken the one-action-at-a-time rule.
- **In-process client.** The lab calls the control plane through Starlette's `TestClient` on loopback, which depends on `httpx` (already a test dependency). The deprecation notice is suppressed at import.
- **Unsigned journal.** The lab journal is unsigned. It is a UI aid, not evidence.
- **Timeline polling.** The timeline re-reads every run's `monitor.jsonl` on each poll. This is fine for the 40-run cap; it is not designed for large histories.
- **Mailbox attack rows.** In the containment probe, the mailbox attack rows (symlink, FIFO, rename, rmdir) are informational. A planted symlink or FIFO succeeding inside the sandbox is expected. The checks that matter are the broker-side ones: delivery as regular files, victim intact, and no blocking.
- **One host, one browser.** Tested on one Fedora host and in one Chromium-based browser pane. No cross-browser or screen-reader audit was done beyond semantic HTML, keyboard-focusable topology nodes, `aria-live` status and reduced motion.
- **Stale stylesheet.** During testing the browser pane kept a stale stylesheet until a reload, even though the console sends `Cache-Control: no-store` on its own responses. A hard reload fixes it.
- **No `validate_repo.sh`.** `tools/validate_repo.sh` does not exist in this tree, so the individual gates were run instead (section 9).
- **Stub model only.** Real-model numbers are precomputed; no real model is run by the console (by instruction).

## 11. Files

New:

```
aegislab/aegis/console.py
aegislab/web/console/index.html
aegislab/web/console/console.css
aegislab/web/console/console.js
aegislab/scripts/start_prototype.sh
aegislab/tests/test_r1_console.py
docs/prototype/PHASE_R1_REPORT.md
docs/prototype/PROTOTYPE_GUIDE.md
docs/prototype/JUDGE_WALKTHROUGH.md
docs/prototype/screenshots/01_overview.jpg … 06_limits.jpg
```

Modified: `README.md` (repository root, not in the manifest).

The following were not modified:

- every file in `MANIFEST.sha256`;
- every Phase 3-pinned source;
- `evidence/`;
- `submission/`, if present;
- release candidates rc1 to rc4;
- signed checkpoints and audit records.

## 12. Commit

Implementation commit on `r1/functional-prototype`: `ea2f8ea204aa41269706d7cc20849090af0904ee`, with parent `f1e28552c2b65c44ebb73351e889053fc1d15c09`. This line was added in a follow-up commit. Nothing is pushed.

## 13. Next tasks (not started; Phase R2 is out of scope here)

1. A human review of the console on a second machine, preferably one without Podman, to exercise degraded mode end to end.
2. Decide whether to publish the branch (push or PR). This needs explicit approval.
3. Optional:
   - per-session random tokens instead of the persistent demo tokens;
   - a signed lab journal;
   - a CI job that runs `tests/test_r1_console.py -m "not podman"`.
4. Optional: record a short screen capture of the walkthrough from the real app for the submission.
