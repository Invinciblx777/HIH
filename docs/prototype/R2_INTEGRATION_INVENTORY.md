# Phase R2 integration inventory (baseline before R2 changes)

Snapshot of `origin/main` at `2bd5b83` (merge of `design/story-archive-ui`, tree identical to `b417c96`), taken on
26 Oct 2026 before any Phase R2 change. Branch for R2 work: `r2/live-security-lab`.

Legend: **W** working, **P** partially working, **PRES** presentational only, **NI** not implemented, **ENV** blocked by
environment.

| # | UI action (console.js) | Endpoint / function | Authorisation | Real operation | Audit / evidence output | Tests | Status |
|---|---|---|---|---|---|---|---|
| 1 | Boot: load identities | `GET /api/demo/identities` (aegis/api.py) | none; only with `AEGIS_DEMO_MODE=1` | returns **all four role tokens** to browser JS | none | `test_demo_identities_stay_off_without_demo_mode` | W, but violates R2 rule "no global role tokens in browser JS" |
| 2 | Header status pill, Overview ledger | `GET /api/lab/status` | none (read-only) | `podman info`, image check, `runs.verify_run` on latest terminal run, verifier subprocess on DEMO-001 | integrity summary | `test_status_*` | W |
| 3 | Lab: "Start a live run" | `POST /api/lab/runs` | operator token from browser | create + freeze + start in one call through `aegis.api` handlers; broker runs real rootless containers | run.created/frozen, broker events, seal | `test_prepare_run_*`, `test_live_run_and_all_scenarios` (podman) | P: no stepwise create/configure/freeze/start, no defence selection |
| 4 | Defence configuration | `POST /api/runs/{id}/defence-config` exists in api.py | blue_participant or operator | writes blue working config before freeze | config.updated | test_phase2_lifecycle | NI in UI |
| 5 | Lifecycle display | `GET /api/runs/{id}` polled every 1.5 s | observer | real run record | — | — | W |
| 6 | Scenario: prohibited-access | `POST /api/lab/scenarios/prohibited-access/run` | operator token from browser | 3 real requests (red, red release, observer) via in-process control plane | 3 policy.denied audit entries, leak scan | `test_prohibited_access_*` | W |
| 7 | Scenario: cross-role-isolation | `.../cross-role-isolation/run` | operator token | blue artifact read, digest redaction blue vs reviewer, forged token | policy.denied + 5 broker denials from monitor stream | `test_cross_role_isolation_scenario` | W |
| 8 | Scenario: authorized-release | `.../authorized-release/run` | operator token (reviewer token used server-side) | real release, strict verify, bundle export | run.released, terminal checkpoint, bundle | `test_authorized_release_*` | W |
| 9 | Scenario: sandbox-containment | `.../sandbox-containment/run` | operator token | fresh hardened container, fixed probe, broker `_write_msg` | checks only (not in a run's audit log) | `test_live_sandbox_containment_probe` (podman) | W (ENV without Podman) |
| 10 | Lab: "Try a request yourself" | browser sends `X-Aegis-Token` straight to `/api/runs/...` | token chosen in browser | real control-plane call | policy.denied for refused reads | none | W, depends on browser tokens |
| 11 | Recorded execution | `GET /api/lab/replay` | none | reads saved transcript | — | none | W |
| 12 | Audit archive | `GET /api/lab/timeline` | none | merged redacted monitor streams | seq, signed flag | `test_timeline_*` | P: monitor stream only, no signed audit-log view, no op/reason, client-side paging only |
| 13 | Connections: topology / hierarchy | static `TOPO` / `HIER` in console.js | — | none | — | — | PRES (honestly labelled static) |
| 14 | Connections: timeline | `GET /api/lab/timeline?run_id=` | none | real events of one run | — | — | W |
| 15 | Graph overlay of scenario results | — | — | — | — | — | NI |
| 16 | Evidence: verify bundle | `POST /api/lab/bundles/{id}/verify` | none | `python -m aegis.verify_cli` subprocess | exit code + findings | `test_shipped_bundles_verify_as_expected` | W |
| 17 | Evidence: tamper disposable copy | `POST /api/lab/bundles/{id}/tamper` | reviewer/operator token from browser | copy, mutate, verify copy + original, digest compare | verdict | `test_tamper_on_disposable_copy_*` | W, depends on browser tokens |
| 18 | Evidence: in-memory tamper suite | browser loops `POST /api/runs/{id}/tamper-test` with reviewer token | reviewer token in browser | real `tamper_test` | 12 rows | none in R1 | W, depends on browser tokens |
| 19 | Evidence: download | `GET /api/lab/bundles/{id}/download` | none | zip of allowlisted files | — | `test_download_*` | W |
| 20 | Experiments | `GET /api/lab/experiments` | none | `check_claims.phase3_rows()`, `timing_rows()` recomputation | — | `test_experiment_figures_*` | W |
| 21 | Interrupted run after console restart | — | — | run stays RUNNING forever (broker thread died with the process) | none | none | NI |
| 22 | Cross-origin / CSRF protection of POSTs | Host allowlist only | — | — | — | `test_non_loopback_host_header_is_refused` | P: no Origin / Sec-Fetch-Site check, no CSRF token |
| 23 | Browser end-to-end tests | — | — | — | — | screenshots only (R1-UI) | NI |

## Gaps R2 must close (P0 first)

1. Items 1, 10, 17, 18: remove role tokens from the browser. Replace with a loopback operator session
   (one-time launch link, HttpOnly SameSite=Strict cookie, per-session CSRF token, Origin / Sec-Fetch-Site check).
   Role actions run server-side with server-held tokens, through the unchanged control plane.
2. Item 3/4: stepwise lifecycle (create, configure defence from fixed profiles, freeze, start, observe, release).
3. Item 21: mark interrupted runs FAILED with a terminal checkpoint on console start.
4. Item 12: signed audit-log view (metadata allowlist, server-side filter and pagination).
5. Item 15: graph overlay from recorded scenario results, labelled as observed vs static.
6. Item 23: browser end-to-end tests with Playwright against the running console.
