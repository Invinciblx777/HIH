# Phase R3.5 security and publication preflight

Date: 26 October 2026. Release candidate: branch `r3/security-hardening`, R3 head `9516944` (local tag `aegislab-r3-rc1`),
based on `main` at `209d386`. This preflight reviewed the R3 change set (`209d386..9516944`, 51 files, +2064 / −180) and the
R3.5 release commit on top of it. All checks ran on the supported host (Fedora, kernel 7.2, rootless Podman 5.8.9,
Python 3.14.8, Node 24.22.0). A passing test suite does not prove the absence of vulnerabilities; this is a review, not an audit.

## 1. Verdict

**No release-blocking vulnerability found.** No High-severity issue. Two low-risk hardening items in the CI workflow were
fixed (section 4). The documented R3 residual risks remain and are restated in section 5; none of them was redesigned in
this phase.

## 2. Security-sensitive R3 changes reviewed (code and tests)

| Area | What the code does (read, not inferred from tests) | Assessment |
|---|---|---|
| Request-body limit (`console.py` `BodyLimit`) | Outermost ASGI middleware. Refuses conflicting or non-numeric `Content-Length` (400), a declared length over 256 KiB (413), and a streamed body whose received bytes pass 256 KiB (413) before any handler runs; buffers at most 256 KiB and replays it; refusals send `Connection: close` and the security headers. Covers the mounted control plane. | Correct. Residual: no body-read timeout (RR-3), up to 256 KiB read before Host/Origin checks (RR-5). |
| Operator authentication (`lab_session.py`) | 192-bit `secrets.token_urlsafe(24)` launch code in `$AEGIS_VAR/console/launch_code` (mode 0600, atomic replace); `hmac.compare_digest`; replaced inside the same lock on success (single use); the launcher's environment code is adopted once per process and state directory and the launcher now unsets it. | Correct. Lockout is global (RR-2). |
| Launch-code expiry | Issue time is the file mtime; an unused code older than 2 h is refused and replaced on the next `launch_code()`. | Correct for the threat model (a same-UID process could touch the file, but it can read the code anyway). |
| CSRF / Origin | Unchanged from R2: per-session CSRF token on writes; `Sec-Fetch-Site` and `Origin` checked on unsafe methods; `Origin: null` is refused. R3 adds security headers to the 403 refusal. | Correct. Non-browser clients without these headers still need cookie + CSRF or a role token (RR-4). |
| Host validation | Unchanged allowlist `127.0.0.1, localhost, [::1]` (421 otherwise); R3 adds security headers to the refusal. | Correct. |
| Session lifecycle | `/session/start` ends the session the browser presented; the server always picks the id; `end()` uses constant-time comparison; idle 2 h, absolute 8 h, max 16 sessions. | Correct. |
| Run idempotency | Optional `X-Aegis-Idempotency-Key` (8–64 chars `[A-Za-z0-9_-]`), keyed by caller (session id or token) inside the lab lock; in memory, 256 entries. | Correct; keys do not survive a restart (RR-9). |
| Authorisation order | `freeze` and `start` authorise before `_require_live()`, so an unauthenticated caller no longer learns the host's Podman status. | Correct. |
| Sandbox execution | No change to `runtime.py`, `runs.py`, `api.py` or the sandbox image (all pinned by `MANIFEST.sha256`, unchanged since `209d386`). | Unchanged. |
| Verification fail-closed | `OSError` launching the verifier is "no verdict" (exit code `None`); the UI shows **No verdict**, never pass or reject; only conclusive shipped-bundle results are cached. | Correct. |
| Symlink protection | A lab bundle directory that is a link is not listed; any listed file that is a link refuses verify (no verdict), tamper (409) and download (409). | Correct. Check-then-use race needs same-UID write access to `var/console/bundles`, out of scope. |
| Audit-log handling | Post-release refusals are read from the pinned control plane's `post_terminal.jsonl` (already in `runs.py`, unchanged) and shown as unsigned with no sequence number; only `ts`, `type`, `actor`, `op`, `reason` are exposed. The signed chain is never reopened. | Correct and honest. Unsigned post-terminal records remain (RR-6). |
| Browser-facing API responses | New fields: `replayed`, `recording`, `post_terminal`, `after_close`. None carries a token, launch code, canary, payload or key. The probe still returns only status, structure and a count of protected values. | No new exposure found. |

## 3. Publication scan

| Check | Result |
|---|---|
| `python3 tools/publication_scan.py --repo . --history` (index + every blob reachable from any ref) | 397 files in the index, 239 further blobs; **0 FAIL, 0 WARN** |
| Allowlist (`tools/publication_allowlist.txt`, 7 rules) reviewed by hand | All 7 still justified: 3 synthetic test keys/tokens (`sk-test-SECRET-KEY-…`, `sk-p3-SYNTHETIC-KEY-…`, `wrong-token-value`), 2 leak-marker paths in tests, the hashed 22 Oct raw timing evidence, the 47 MB pitch video. The scanner lets allowlist rules suppress FAIL kinds too; no rule covers a real secret. |
| R3 diff grepped for launch codes, CSRF values, home paths, private IPs, key blocks | none (only `secrets.token_urlsafe(24)` calls and the review's description of it) |
| Tracked runtime state (`var/`, `launch_code`, `tokens.json`, keys, `.env`, `.venv*`) | none; `var/`, `.venv/`, `.venv-browser/` are git-ignored. Tracked `audit.jsonl` and `.log` files are pre-existing frozen evidence. |
| Screenshots (`docs/prototype/screenshots/r3/`, 37 PNG) spot-checked | headless captures, no URL bar, no code or token visible |
| Large files | largest is the 47 MB pitch video (allowlisted, below GitHub's 100 MB limit) |
| Frozen evidence | `sha256sum -c MANIFEST.sha256`: 259 entries OK; `MANIFEST.sha256` itself unchanged since `209d386` |
| Confidential red/blue artifacts via the UI | none added; R2's `test_no_role_token_or_launch_code_reaches_the_browser` and the R3 probe/audit tests pass |

## 4. Fixed in this phase (CI workflow only)

| ID | Finding | Fix |
|---|---|---|
| R35-01 (Low) | Actions referenced by mutable tags (`@v4`, `@v5`): a moved tag would run different code with the job's token. Was R3 residual RR-11. | Pinned to commit SHAs resolved from the exact release tags on 26 Oct 2026: `actions/checkout` v4.4.0 `11d5960a…`, `actions/setup-python` v5.6.0 `a26af69b…`, `actions/upload-artifact` v4.6.2 `ea165f8d…`. |
| R35-02 (Low) | `actions/checkout` left the `GITHUB_TOKEN` in `.git/config` while the job runs repository code (tests, browser). | `persist-credentials: false`. The job needs no write access (`permissions: contents: read`). |

Workflow review otherwise: `pull_request` (not `pull_request_target`), no secrets referenced, `permissions: contents: read`,
`timeout-minutes: 30`, one gate script with `--strict` (a skipped gate fails the job), logs uploaded with `if: always()`,
Python packages installed with exact constraints, Playwright pinned to 1.64.1. Podman-only checks are not claimed by CI.

## 5. Remaining limitations (unchanged, accepted for a local single-operator prototype)

1. **Cookies shared across ports on 127.0.0.1** (RR-1): any other HTTP service on loopback that the browser visits
   receives the console cookie. Mitigation: dedicated browser profile, **End session** after use.
2. **Single local operator** (RR-10): not multi-user authentication; global per-role demo tokens.
3. **Unsigned post-terminal audit records** (RR-6): labelled unsigned in the UI and API, outside the verified evidence.
4. **Global login lockout** (RR-2): 20 wrong codes block logins for 60 s; availability only.
5. **Slow request bodies** (RR-3): no body-read timeout; bounded at 256 KiB per request; local only.
6. **Hosted CI covers only the container-free gates.** The workflow passed on GitHub for `52db77d`
   (`R35_GITHUB_CI_RESULTS.md`). The Podman-dependent checks are proven only on the Fedora host.

**The console must not be exposed on a network or a public URL.** It launches real sandboxes and the process holds the
broker's signing key. A public source repository does not mean a hosted working instance exists.

## 6. Observation (not a vulnerability)

The browser tests write their screenshots into the tracked directory `docs/prototype/screenshots/r3/`, so running the
gates leaves modified PNGs in the working tree. During this preflight they were restored with
`git checkout -- docs/prototype/screenshots/r3/` after each run; the committed screenshots are those of Phase R3.
