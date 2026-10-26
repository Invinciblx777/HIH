# Phase R3 security review: AegisLab prototype console

Date: 26 October 2026. Branch `r3/security-hardening`, based on `main` at `209d386` (merge of PR #4, Phase R2).
Scope: `aegislab/aegis/console.py`, `aegislab/aegis/lab_session.py`, the console UI (`aegislab/web/console/`), the launcher
`aegislab/scripts/start_prototype.sh`, and how they drive the pinned control plane (`aegis/api.py`, `runs.py`,
`evidence.py`, `verify_cli.py`; unchanged, hashes in `MANIFEST.sha256`). All testing was local: the console on 127.0.0.1,
rootless Podman on this host, synthetic fixtures. No third-party system was contacted.

A passing test suite does not prove the absence of vulnerabilities. This review lists what was examined, what was found,
what was fixed, and what remains.

## 1. Threat model of the console

**What the console is.** A loopback web console for one trusted local operator. The operator proves possession of a
launch code once and gets a session; inside it the console performs the requests of four demonstration roles
(operator, reviewer, blue participant, red participant) server-side, with the control plane's own role tokens, through
the unchanged role checks. Role selection in the UI is **not** tenant authentication: the roles are not separate people.

**Assets.** Role tokens (`var/console/keys/tokens.json`), the broker's Ed25519 signing key, hidden canaries and red's
payloads, sealed model outputs, the defence rules, the signed audit chain and its checkpoints, the launch code and
session cookie, and the integrity of what the UI tells a judge.

**Adversaries considered.**

| Adversary | Can | Cannot (assumed) |
|---|---|---|
| A web page in the operator's browser (any origin) | make the browser send requests to 127.0.0.1 (simple and preflighted), use DNS rebinding | read cross-origin responses; set `Origin`/`Sec-Fetch-Site` |
| Another process or user on the same host | connect to 127.0.0.1:8400 with any bytes and headers | read files of the operator's user (mode 0600) |
| A participant role inside the lab | everything its role token allows via the control plane | reach the console's session, the broker key or other roles' tokens |
| Someone who later sees the launch link (browser history, terminal scroll-back, a screenshot or recording) | open the link | — |
| A bundle on disk modified by the local user | replace files, plant symbolic links | change the pinned key or the recorded terminal hash |

Out of scope, unchanged from R2: a compromised broker or signing key, a malicious local user with the operator's own
UID (it can read every file), kernel or container-runtime escapes, multi-user authentication.

## 2. Findings

Severity is for this deployment (loopback console, local demo). Each fix has a regression test that fails on the R2
code (`docs/prototype/PHASE_R3_EXECUTION_REPORT.md` section 6 lists which tests fail on `209d386`).

| ID | Severity | Component | Finding | Fix | Regression test |
|---|---|---|---|---|---|
| R3-01 | Medium | `console.py` request guard | **Body limit relied on `Content-Length`.** A chunked body (no length) of any size was read in full and parsed before any check: reproduced with 8 MiB chunked POSTs to `/api/lab/runs`, `/api/lab/runs/LAB-001/defence` and the mounted `/api/runs/LAB-001/defence-config`, all **unauthenticated** (responses 422/403 came only after the whole body was read; peak RSS 116 MB vs 66 MB after the fix). Any local process could exhaust memory. A browser page cannot send a chunked body over HTTP/1.1, so the reach is local processes. | `BodyLimit`, plain ASGI middleware, outermost: refuses a declared length over 256 KiB, malformed or conflicting `Content-Length` (400), and any body whose received bytes exceed 256 KiB (413), **before** any handler runs, including handlers that never read their body; buffers at most 256 KiB, replays it to the app; refusals carry `Connection: close` and the security headers. | `test_streamed_body_over_the_limit_never_reaches_the_app_and_reading_stops`, `test_real_server_refuses_a_streamed_body_without_content_length` (raw socket, real uvicorn), `test_oversized_bodies_change_no_session_or_run_state`, `test_mounted_control_plane_is_covered_by_the_limit`, 8 more |
| R3-02 | Medium | `lab_session.py`, launcher | **Launch code reusable for the whole process lifetime.** The link sits in browser history, terminal scroll-back and, in a recorded demo, on screen; anyone who later opens it (another browser profile, another local user who sees the screen) gets a full operator session. No expiry. | Code is **single-use** (replaced atomically, mode 0600, inside the same lock as the comparison, so two concurrent uses cannot both succeed) and **expires** after 2 h unused. `start_prototype.sh --link` issues a fresh link for a running console. The launcher now writes the code to the state file instead of passing it through the environment. | `test_launch_code_works_once_and_is_replaced_by_a_fresh_private_one`, `test_concurrent_use_of_one_launch_code_starts_exactly_one_session`, `test_unused_launch_code_expires`, `test_issuing_a_new_link_invalidates_the_unused_one`, `test_launcher_environment_code_is_single_use_too`; browser: second use of the link refused |
| R3-03 | Low | `console.py` `/session/start` | A new login did not end the session the browser already held; old session ids stayed valid until expiry (up to 16). | Login ends the presented session; the server always chooses the session id (no fixation: a planted cookie value is never adopted). | `test_a_new_login_ends_the_previous_session`, `test_a_planted_session_id_is_never_adopted` |
| R3-04 | Low | `console.py` freeze/start | **Availability check before authorisation**: an unauthenticated POST to `/api/lab/runs/{id}/freeze` or `/start` got 503 with the host's Podman status instead of 403. Found by the new container-free browser test. | Authorise first. | `test_authorisation_is_checked_before_the_host_is_described`, browser `test_end_session_returns_to_read_only` |
| R3-05 | Medium (integrity of the UI) | probe and audit views | **Misleading audit reporting after release.** For a refusal against a RELEASED run the UI said "this operation is not logged when refused". In fact the control plane writes it to `post_terminal.jsonl` (unsigned, informational) because the signed chain is closed. Conversely, the audit-log view never showed those events. A judge could not tell a signed denial, an unsigned post-close record and an unrecorded request apart. | The probe returns `recording.where` = `audit_chain` / `post_terminal` / `counted_only` (denial cap) / `not_recorded`, plus the post-close entries, all marked `signed: false` with no sequence number. The audit-log endpoint returns `after_close` (count, last 50 entries, note) and the UI lists them separately as unsigned. The sealed chain and vault are never touched (asserted byte-for-byte). | `test_refusal_after_release_is_reported_as_unsigned_and_the_chain_stays_closed`, `test_refusal_on_a_sealed_run_is_reported_as_a_signed_chain_entry`, `test_unlogged_requests_are_reported_as_not_recorded`; browser step 9 of the live flow |
| R3-06 | Low | `POST /api/lab/runs` | Duplicate create (network retry, second tab, script) created a second run and workload. The UI button guard prevented double clicks only within one page. | Optional `X-Aegis-Idempotency-Key`, scoped to the caller (session or token); a repeat returns the original run with `replayed: true`. The UI sends one key per click. | `test_idempotency_key_returns_the_original_run_instead_of_a_second_one`, `test_concurrent_duplicate_creates_spawn_one_run`; live: 6 parallel duplicates, 1 run |
| R3-07 | Low | evidence centre | Lab bundle directories and files were followed through symbolic links by the verifier subprocess, the tamper copy and the digest comparison (download skipped links silently and produced an incomplete zip). Needs write access to `var/console/bundles` (same UID), so low. | A bundle whose directory or any listed file is a symbolic link is refused for verify (no verdict), tamper (409) and download (409); a symlinked bundle directory is not offered at all. | `test_symbolic_links_in_a_lab_bundle_are_refused`, `test_a_symlinked_bundle_directory_is_not_offered` |
| R3-08 | Low | evidence centre, status | A verifier that cannot be started raised an unhandled `OSError` (500). An inconclusive shipped-bundle verification (busy slot, timeout) was cached on the status page for an hour. | `OSError` is reported as no verdict; only a conclusive result is cached. The UI says "No verdict" instead of "Rejected" when there is no exit code. | `test_verifier_that_cannot_start_is_no_verdict`, `test_status_does_not_cache_an_inconclusive_shipped_verification` |
| R3-09 | Low | scenario/tamper records | Tamper demonstrations run outside the lab lock; concurrent ones could pick the same result number and overwrite a record. | Result numbering under a lock. | `test_concurrent_tamper_demonstrations_leave_the_original_and_no_copies` |
| R3-10 | Info | request guard | Early refusals (421 foreign Host, 403 cross-origin) lacked the security headers, including `Cache-Control: no-store`. | Headers added. | `test_real_server_refuses_foreign_host_headers` |
| R3-11 | Info (process) | test harness | Browser tests were not reproducible (Playwright outside any requirements file) and a missing browser showed up only as one generic skip. | `requirements-browser.txt`, `constraints.txt`, `scripts/run_browser_tests.sh` with PASS / FAIL / SKIPPED / BLOCKED, `AEGIS_REQUIRE_BROWSER` / `AEGIS_REQUIRE_PODMAN`. | the runner itself; `release_gates.sh --strict` |

No finding was rated High. None of the findings gave access to a role token, the signing key, a canary or sealed data.

## 3. Operator-session review (item by item)

| Item | Status after R3 | Evidence |
|---|---|---|
| Launch-code entropy and generation | `secrets.token_urlsafe(24)`, 192 bits, compared with `hmac.compare_digest` | code review |
| Launch-code expiration | 2 h unused (file mtime is the issue time) | `test_unused_launch_code_expires` |
| Launch-code single use | yes, atomic replacement under the same lock as the comparison | concurrency test, 8 threads, exactly 1 session |
| Exposure via history / logs / referrer | history: single use makes the stale link useless. Logs: the launcher runs uvicorn at `--log-level warning` (no access log); a manual start at info level would log the URL, which single use again neutralises. Referrer: `Referrer-Policy: no-referrer`; the redirect target `/#/lab` carries no code. | `test_session_responses_are_not_cached_and_leak_no_referrer` |
| Session fixation | server chooses the id; planted values ignored | `test_a_planted_session_id_is_never_adopted` |
| Rotation at authentication | new id on every login; the previous one is ended | `test_a_new_login_ends_the_previous_session` |
| Expiry | 2 h idle, 8 h absolute | `test_idle_and_absolute_session_expiry` |
| Logout / revocation | `POST /api/lab/session/end` (CSRF) and a new **End session** control in the header | browser `test_end_session_returns_to_read_only` |
| Guessing and lockout | 20 wrong codes → 60 s global lockout; with 192-bit single-use codes guessing is infeasible regardless | existing R2 test; residual RR-2 |
| Cookie scope and attributes | `aegis_console`, HttpOnly, SameSite=Strict, Path=/, Max-Age 8 h, host-only; no `Secure` (plain HTTP on loopback) | browser test reads the cookie flags |
| CSRF binding | per-session token; another session's valid token is refused | `test_csrf_token_is_bound_to_its_session` |
| Cross-origin requests | `Origin` and `Sec-Fetch-Site` checked on every unsafe method, console and mounted control plane | R2 tests (5 header variants) |
| DNS rebinding / Host | Host allowlist (127.0.0.1, localhost, [::1]) → 421 | `test_real_server_refuses_foreign_host_headers` |
| Browser cache | `Cache-Control: no-store` on every response including refusals | as above |
| Leakage through frontend JS | no role token, launch code or key in any page or API response | R2 `test_no_role_token_or_launch_code_reaches_the_browser` |
| Process restart | sessions are in memory and end; the launcher issues a new code | live adversarial check B |
| Multiple windows / concurrent sessions | one cookie per browser profile, shared by its windows; other browsers need `--link`; at most 16 sessions (least recently used evicted) | browser test opens a second context |

## 4. Run lifecycle and audit integrity

- Lifecycle steps run under one non-blocking lab lock (409 for a concurrent action). The control plane refuses
  unsupported transitions (409) and the state is unchanged afterwards (`test_unsupported_transitions_fail_cleanly_and_leave_state`).
- Six concurrent `start` requests: exactly one 200, one broker, one `run.sealed` (unit test and live check).
- The UI shows a run ID and a state only from server responses; a replayed create says so.
- **Interrupted container** (live): killing the red sandbox mid-run ended the run SEALED with `complete: false`
  (3 of 10 attacks evaluated). It is labelled incomplete in the run record and in the signed `run.sealed` entry; it is
  not presented as complete. The control plane still allows releasing an incomplete run (pinned behaviour).
- **Console killed mid-run** (live): on restart the run is FAILED, with a signed terminal checkpoint, `verify_run` ok and
  terminal-verified, no containers left, and it can never be released (409).
- **After release** the signed chain is closed and is never reopened (R2 design kept). Refusals afterwards are kept in
  `post_terminal.jsonl`, unsigned and outside the evidence the verifier checks; the console now says exactly that.

## 5. Evidence verification

| Requirement | Status |
|---|---|
| Uses the strict verifier | `python -m aegis.verify_cli` subprocess, unchanged; lab bundles verified with the broker key pinned and the terminal hash recorded at release |
| Authentic passes / tampered fails | live: LAB bundle exit 0; truncated copy exit 1; shipped VAL-001-TAMPERED exit 1 |
| Missing trust anchor fails closed | verifier behaviour (pinned; R2/Phase 2 tests); legacy DEMO-001 without a terminal checkpoint is rejected by design |
| Only the exact pair counts | PASS needs exit 0 **and** `ok: true` (or exit 1 **and** `ok: false` for an expected failure); exit 2, a timeout, a launch failure or unparsable output is never a pass | parametrised test with 6 combinations |
| Malformed bundle | verify returns exit ≠ 0, `matches_expectation: false`, HTTP 200 (no crash) |
| Original never modified | SHA-256 of every bundle file compared before/after each tamper demonstration, also with 4 concurrent ones |
| No arbitrary paths | bundle ids are registry keys; traversal and encoded variants give 404; non-genuine bundles are not downloadable |
| Symbolic links | refused (R3-07) |
| Concurrency | 2 verifier slots (429 beyond), temporary copies in separate `mkdtemp` directories, all removed |

## 6. Residual risks (accepted, documented)

| ID | Risk | Why accepted / mitigation |
|---|---|---|
| RR-1 | **Cookies are not isolated by port.** If the operator's browser visits another HTTP service on 127.0.0.1 (any port), that service receives the `aegis_console` cookie and could, as a non-browser client, read the CSRF token and act as the operator. | Needs TLS and a `__Host-` cookie, or a dedicated host name per service. For the demo: use a dedicated browser profile, do not browse other local web services while the console runs, press **End session** afterwards. |
| RR-2 | The launch-code lockout is global: any local process can send 20 wrong codes and block logins for 60 s at a time. | Availability only; guessing is infeasible anyway. Restarting the console or waiting a minute recovers. |
| RR-3 | A client that trickles its body slowly holds a connection (no body-read timeout in uvicorn). | Local only; bounded by 256 KiB per request. |
| RR-4 | Clients that send neither `Origin` nor `Sec-Fetch-Site` (curl, scripts) are not cross-origin-checked. | They are not a browser acting for someone else; they still need the cookie and CSRF token, or a role token. |
| RR-5 | Up to 256 KiB of a request body is read before the Host and Origin checks. | Bounded; needed so the limit also covers handlers that never read their body. |
| RR-6 | Post-release refusals are unsigned (`post_terminal.jsonl`, capped at 1000 per run). | Signing them would mean reopening a sealed chain; deferred as a trust-model change. The UI labels them unsigned. |
| RR-7 | A broker thread that dies while the console keeps running is caught only by the broker's 300 s deadline; recovery of interrupted runs happens at start-up. | Unchanged from R2. |
| RR-8 | `POST /api/lab/bundles/{id}/verify` and bundle download need no session. | Read-only; 2 verifier slots; download only for genuine released bundles, consistent with the control plane (`GET /api/runs/{id}/evidence` is public after release). |
| RR-9 | Idempotency keys live in memory; after a restart the same key creates a new run. | Restart already ends every session. |
| RR-10 | One local operator, not multi-user authentication; global per-role control-plane tokens. | Unchanged; stated in the UI and the guide. |
| RR-11 | GitHub Actions are pinned by version tag, not commit SHA; the workflow has not run on GitHub yet (nothing was pushed). | First run happens when the branch is pushed with approval. |
