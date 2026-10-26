# Phase R2 execution report: live security lab and end-to-end prototype integration

Date: 26 October 2026. Branch: `r2/live-security-lab` (local only, not pushed). Verdict: see section 16.

## 1. Baseline discovered

- Repository `round2/work/HIH`, `origin/main` at `2bd5b83` (merge of PR #3, `design/story-archive-ui`; tree identical to
  `b417c96`). R2 work branches from that commit.
- The control plane (`aegis/api.py`, `runs.py`, `evidence.py`, ...) is pinned by the Phase 3 evidence and by
  `MANIFEST.sha256` (259 entries). None of those files was edited; the console wraps them.
- Baseline gates recorded for the start of R2 (`PHASE_R1_REPORT.md`, tree unchanged since by R1-UI except the
  console UI and docs): full pytest suite 386 passed; judge demo 17/17; security demo 34/34 plus 1 documented limit; `check_claims.py` 14/14 + 72/72 + 48/48
  (134 checks); `check_presentation.py` 157/157; `sha256sum -c MANIFEST.sha256` OK.
- The R2 brief quotes a baseline of 345 tests; the suite on this tree already had 386 (R1 added 41).
- The full integration inventory taken before any change is `docs/prototype/R2_INTEGRATION_INVENTORY.md` (23 items).

## 2. Redesigned UI branch and revision

The archive-style console from Phase R1-UI: `ee98ff8` on `design/story-archive-ui`, merged to `main` by PR #2
(`8413e99`) and PR #3 (`2bd5b83`, after `b417c96` removed the legacy static site). R2 keeps its typography, tokens,
ring-highlight navigation, sheets, cards and layout. New elements reuse the existing classes and colour tokens only.

## 3. Features that were already functional (R1)

Status page, live run (create + freeze + start in one call), the four scenarios (prohibited access, cross-role
isolation, authorised release, sandbox containment), redacted monitoring stream, strict bundle verification through
`aegis.verify_cli`, disposable-copy tampering, bundle download, recomputed experiment figures, recorded replay in
degraded mode, loopback Host allowlist, security headers, body limits, lab lock.

What was not acceptable for R2 (inventory items 1, 10, 17, 18): the browser fetched all four role tokens from
`/api/demo/identities`, which needed `AEGIS_DEMO_MODE=1`, and sent them itself.

## 4. Features implemented in this phase

| Area | What changed |
|---|---|
| Identity | New `aegis/lab_session.py`: one-time launch code, HttpOnly SameSite=Strict session cookie, per-session CSRF token, idle/absolute expiry, lockout after 20 wrong codes. Role tokens never leave the server. `AEGIS_DEMO_MODE=1` is refused at start-up. |
| Cross-origin | `Origin` and `Sec-Fetch-Site` checked on every state-changing request, for the console routes and the mounted control plane. |
| Lifecycle | Stepwise `POST /api/lab/runs` (create, `stop_after: created`), `/defence`, `/freeze`, `/start`; `GET /api/lab/runs/{id}` with state, events, signed-up-to, next actions. Fixed defence profiles: sample, hardened, none. |
| Recovery | On start-up a LAB run left RUNNING with no broker thread is marked FAILED, with `run.failed` and a signed terminal checkpoint; its containers are stopped. |
| Scenario records | Every scenario and tamper result is saved (`var/lab/results`, capped at 200) and listed by `GET /api/lab/results`. |
| Signed audit log | `GET /api/lab/runs/{id}/audit`: metadata allowlist, server-side filters (type, actor, decision), pagination (≤500), checkpoint coverage, terminal anchor. Outcomes only after release. UI: Audit page, *Signed audit log* view. |
| Request probe | `POST /api/lab/probe`: allowlisted role × operation, sent server-side; returns status, decision, response structure, protected-value count and the audit entries it produced. |
| Tamper suite | `POST /api/lab/runs/{id}/tamper-suite`: the 12 in-memory modes, server-side, with a before/after digest of the stored log. |
| Graph | *Observed* overlay on the topology from recorded results, marked separately from the static architecture. |
| Modes | Execution mode labels: LIVE SANDBOX · STUB MODEL, LIVE SYSTEM TEST, REPLAY · RECORDED, PRECOMPUTED REAL-MODEL, UNAVAILABLE. |
| Launcher | Prints the launch link, unsets `AEGIS_DEMO_MODE`, help range fixed. |
| UI fixes | Confirmation dialog resolves on submit (some Chromium builds never fire `close`); no horizontal overflow at 1024 px; tamper-mode choice kept after a run. |

## 5. Actual backend/API integration

Every console action calls the unchanged control plane in-process (`TestClient(api.app)`) with the server-held token
of the acting role, so `api.need`, the result gate, the broker and the audit log decide exactly as they do for any
client. The browser only talks to `/api/lab/*` with its session cookie and CSRF header. Each lifecycle response lists
the real calls it made (`operator POST /api/runs 200`, `blue_participant POST /api/runs/LAB-001/defence-config 200`, ...),
and the UI shows them under *Last step*.

## 6. Working run lifecycle

CREATED → (defence as blue) → FROZEN → RUNNING → SEALED → RELEASED, or FAILED. The run ID appears in the UI only
after the server returns 200. A defence change after freeze is refused by the control plane (409) and logged as
`policy.denied`. A second freeze or start gets 409; six concurrent freeze clicks freeze exactly once. Starting is
refused while another run is RUNNING. Interrupted runs become FAILED with a verifiable terminal checkpoint.

## 7. Real scenario execution evidence

Browser run captured by `tests/browser/test_console_browser.py` against a fresh console and real rootless containers
(screenshots in `docs/prototype/screenshots/r2/`):

| Scenario | Observed |
|---|---|
| Run lifecycle (hardened profile) | LAB-001 CREATED → FROZEN → RUNNING → SEALED, 10 of 10 attacks evaluated, 25 audit entries signed up to #25 |
| B · prohibited access | PASS: 3 × HTTP 403 DENIED, each with a `policy.denied` audit entry; run still SEALED |
| B · cross-role isolation | PASS: blue refused and logged, digests hidden from blue, forged token 401, 5 broker denials |
| C · sandbox containment | PASS: fresh container with red's flags; network, DNS, rootfs write and foreign paths refused |
| A · authorised release | RELEASED via the confirmation dialog; outcomes `blocked_input 8 · safe_output 2`; terminal hash shown |
| D · strict verify | LAB-001 exit 0, as expected, broker key pinned, terminal hash pinned |
| D · disposable tamper | `edit_event`: copy exit 1 (rejected), original exit 0, byte-identical before and after |
| D · in-memory suite | 12 of 12 modifications detected; stored log unchanged |
| Probe | observer → release: HTTP 403 "only an authorised reviewer can release results" |

The same flow ran by hand in the in-app browser on the development console (LAB-003, hardened profile, released with
`blocked_input 8 · safe_output 2`). The container-free tests drive the identical code with in-process fake workloads;
the podman-marked test `test_live_stepwise_lifecycle_in_real_containers_through_the_session` drives it in real
containers with the `none` profile and checks that unsafe outputs do get through without a defence.

## 8. Audit and cryptographic verification behaviour

Unchanged: hash-chained `audit.jsonl`, Ed25519 checkpoints held in the reviewer vault, terminal anchor at release or
failure, `verify_cli` as an independent subprocess, 7 disposable-copy and 12 in-memory tamper modes. New in R2 is only
how they are shown: the signed audit log view (with which checkpoint covers each entry), and the tamper suite run
server-side. A verifier that times out returns no exit code and never counts as a match or a PASS (tested).

## 9. Security review of new endpoints

| Endpoint | Authorisation | Inputs | Notes |
|---|---|---|---|
| `GET /session/start` | launch code (constant-time) | `code` | 303 + cookie; 403 otherwise; lockout after 20 failures |
| `GET /api/lab/session` | none | — | CSRF only with a valid cookie; no CORS, so other origins cannot read it |
| `POST /api/lab/session/end` | session + CSRF | — | revokes the session |
| `POST /api/lab/runs` | session + CSRF, or operator token | bucket enum, profile enum, `stop_after` literal | unknown fields 422; lab lock; run limit 40 |
| `POST /api/lab/runs/{id}/defence\|freeze\|start` | as above | `LAB-nnn` that exists; profile enum | lock; state checks by the control plane |
| `GET /api/lab/runs/{id}` | none (read-only public view) | `LAB-nnn` | `public_view` of the control plane, no secrets |
| `GET /api/lab/runs/{id}/audit` | session, or operator/reviewer token | offset, limit ≤500, type/actor/decision/order | metadata allowlist; payload/config digests never returned |
| `POST /api/lab/probe` | session + CSRF | role enum × op enum × `LAB-nnn` | no free path; raw response stays on the server |
| `POST /api/lab/runs/{id}/tamper-suite` | session + CSRF, or operator token | fixed mode list | stored log digest compared before/after |
| `GET /api/lab/results`, `/defence-profiles`, `/probe-ops` | none | scenario enum, limit ≤50 | read-only |

Global: loopback bind, Host allowlist (421), Origin/Sec-Fetch-Site check (403), 256 KiB body limit (413), CSP
`default-src 'self'`, no wildcard CORS, no API docs. Nothing from the browser becomes a command, path, image, container
option or network target. Reviewed residual risks are listed in section 14.

## 10. Actual test commands and exit codes

Run from `aegislab/` on 26 Oct 2026 with `PYTHONDONTWRITEBYTECODE=1`, on Fedora, Podman 5.8.9 rootless:

| Command | Result | Exit |
|---|---|---|
| `.venv/bin/python -m pytest -q` (includes podman tests) | 414 passed, 1 skipped (browser module, no Playwright in `.venv`) | 0 |
| `bash scripts/judge_demo.sh` | 17/17 checks behaved as expected | 0 |
| `bash scripts/security_demo.sh` | 34/34 checks, 1 documented limit (not counted) | 0 |
| `.venv/bin/python evaluation/check_claims.py` | 14/14, 72/72, 48/48 (134 checks) | 0 |
| `.venv/bin/python evaluation/check_claims.py --full` | completed (also re-runs the timing permutation tests); last line 48/48 Phase 3 checks pass | 0 |
| `.venv/bin/python evaluation/check_presentation.py` | 157/157 | 0 |
| `sha256sum -c MANIFEST.sha256` (repo root) | all OK | 0 |

New R2 tests, reported separately:

| Command | Result | Exit |
|---|---|---|
| `.venv/bin/python -m pytest -q tests/test_r2_lab.py -m "not podman"` | 27 passed, 1 deselected (the podman test) | 0 |
| `.venv/bin/python -m pytest -q tests/test_r2_lab.py -m podman` | 1 passed (real containers, 2.5 s) | 0 |
| `<playwright venv>/bin/python -m pytest -q tests/browser` | 3 passed (desktop flow, phone widths, wrong launch code) | 0 |
| `bash scripts/start_prototype.sh --port 8466` with `AEGIS_DEMO_MODE=1` in the environment | launcher unset it; checks ok, LIVE; launch link 303 to `/#/lab`; session authenticated | — |

The browser module is skipped (1 skipped) in the main suite, whose virtualenv has no Playwright.

## 11. Browser and screenshot validation

`tests/browser/test_console_browser.py` (Playwright 1.64.1, Chromium) starts its own console on a free loopback port
with a private state directory, then: checks read-only mode, opens the launch link, checks the cookie is HttpOnly and
SameSite=Strict and invisible to page JavaScript, runs the lifecycle and scenarios A–D through real clicks, opens the
signed audit log and the graph overlay, sends a probe, and checks that requests without CSRF, from another origin or
without the cookie are refused. It fails on any page error or console error, and on horizontal overflow on any page.
A second test repeats the main pages at 390 × 844 (mobile emulation). Screenshots of the real states:
`docs/prototype/screenshots/r2/01_…10_*.png` and `05b_sandbox_containment.png` (1440 × 900) and `m01_…m06_*.png` (phone).

## 12. Exact start-up instructions

```bash
cd HIH/aegislab
bash scripts/start_prototype.sh --reset      # checks, builds the image if needed, prints the launch link
```

Open the printed `http://127.0.0.1:8400/session/start?code=…` in a browser on the same machine. Without it the
console is read-only at `http://127.0.0.1:8400`. `--check` runs the checks only; `--port N` changes the port. Details:
`docs/prototype/PROTOTYPE_GUIDE.md`. Judge path: `docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`.

## 13. Changed files

New: `aegislab/aegis/lab_session.py`, `aegislab/tests/test_r2_lab.py`, `aegislab/tests/browser/test_console_browser.py`,
`docs/prototype/R2_INTEGRATION_INVENTORY.md`, `docs/prototype/PHASE_R2_EXECUTION_REPORT.md`,
`docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`, `docs/prototype/screenshots/r2/*.png`.

Modified: `aegislab/aegis/console.py`, `aegislab/web/console/console.js`, `console.css`, `index.html`,
`aegislab/scripts/start_prototype.sh`, `docs/prototype/PROTOTYPE_GUIDE.md`, `docs/prototype/JUDGE_WALKTHROUGH.md`
(pointer to the new walkthrough), root `README.md`.

Not modified: every file in `MANIFEST.sha256` (including `aegis/api.py`, `runs.py`, `evidence.py`, `aegislab/README.md`),
rc1–rc4 and all experiment evidence, the submission files.

## 14. Known limitations

- **One local operator, not multi-user authentication.** Whoever holds the launch link drives every demonstration
  role. Role switching shows the control plane's decisions; it does not prove that separate people are separated.
  The control plane's tokens remain global per role (`var/keys/tokens.json`), as before.
- **Stub model.** Live runs use the deterministic stub. Real-model figures are precomputed and only recomputed from
  files; no model runs in the console.
- **Single host.** All containers share the host kernel; the broker and signing key are trusted.
- **Clients without Origin/Sec-Fetch-Site** (curl, scripts) are not cross-origin-checked; they still need a token or
  the session cookie plus CSRF token.
- **Body limit by Content-Length.** A chunked request body without Content-Length is limited by the server's
  defaults, not by the 256 KiB check (unchanged from R1).
- **After release the audit log is closed.** Refusals sent to a released run (for example by the probe) get their
  403 but no new audit entry; the UI says so.
- **Recovery is at start-up only.** A run whose broker thread dies while the console keeps running relies on the
  broker's own 300 s deadline to fail closed.
- **Sessions live in memory.** Restarting the console ends every session; the launcher prints a new link.
- **Browser tests need Playwright**, which is not in the console's virtualenv; they were run from a separate one.

## 15. Git status and commit SHA

See the final section of the chat handoff for the commit SHAs. All work is committed locally on `r2/live-security-lab`;
nothing was pushed, merged or deployed.

## 16. Remaining work and verdict

Remaining work (not blockers for this phase): a multi-user identity model, if the console is ever used by more than one
person; Playwright in a pinned dev-requirements file; a chunked-body size limit at the ASGI layer.

Definition-of-done check: the redesigned frontend launches; backend communication works; an authorised operation
(release) runs; unauthorised operations are denied and audited; a complete lifecycle is demonstrable; audit events
connect to real actions; strict verification passes on authentic evidence; a tampered copy is rejected; no command
execution interface exists; browser controls need the session, CSRF token and same origin; old tests pass; new
end-to-end tests pass; start-up is reproducible from the launcher; the design is intact; no fabricated live results
are shown.

Verdict: **PASS — END-TO-END PROTOTYPE VERIFIED**, with the single-operator identity model stated as a limitation
(section 14), as the brief allows when genuine multi-user separation is not enforced.
