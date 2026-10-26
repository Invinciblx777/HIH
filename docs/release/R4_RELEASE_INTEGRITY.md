# R4 release integrity

Phase R4, 26 October 2026. What was checked to show that the merged prototype, its evidence and the historical release
material are intact, and that the new R4 material exposes no secret. Status words: VERIFIED (checked by a command whose
output is kept), REPORTED_ONLY (stated by a record, not re-checked), NOT_RUN, BLOCKED, HUMAN_APPROVAL_REQUIRED.

## Revisions

| Item | Value | Status |
|---|---|---|
| Public `main` | `743415223e916d31c43c48f648d31524c8ba1d88`, merge of PR #5 (26 Oct 2026 17:38:12 UTC); `git ls-remote` HEAD = `refs/heads/main` = this SHA | VERIFIED |
| Hosted CI on `main` | run 40370478665 (`push`), job `gates` success, artifact summary `0 failed, 0 skipped` | VERIFIED (`gh run view`, artifact downloaded) |
| R4 working branch | `r4/final-prototype` from `7434152`: `2df9670` (graph caption, lifecycle gap), `70665a8` (phone button wrap), then the documentation commit that adds this file | VERIFIED locally; **not pushed, not merged** |
| Unpushed R3.5 record commit `1cdca1b` | on local `r3/security-hardening` only; not in `main`. Its text is re-applied in the R4 documentation commit with a post-merge addendum, not cherry-picked | VERIFIED |
| Local tag `aegislab-r3-rc1` | annotated tag on `9516944`, unchanged, not published | VERIFIED |

## Frozen and historical material

| Item | Check | Result | Status |
|---|---|---|---|
| `MANIFEST.sha256` (259 pinned files) | `sha256sum -c MANIFEST.sha256` on `7434152` and on the R4 branch | 259 entries OK; no pinned file edited by R4 | VERIFIED |
| `aegislab/evidence/` (signed bundles DEMO-001, VAL-001, Phase 3 raw results) | `git diff 7434152..r4/final-prototype -- aegislab/evidence` | empty | VERIFIED |
| Shipped bundles verify | `check_claims.py` gate and the Evidence page: DEMO-001 and VAL-001 accepted, VAL-001 TAMPERED rejected | as expected | VERIFIED |
| R3 screenshots `docs/prototype/screenshots/r3/` and R2 set | browser gates overwrite r3 PNGs; restored with `git checkout --` after every run; R4 screenshots go to `screenshots/r4/` | unchanged in every R4 commit | VERIFIED |
| Release candidate `round2/candidates/r3_rc1/` (workspace) | `sha256sum -c SHA256SUMS` | OK | VERIFIED |
| Older candidates rc1 to rc4 | not present under `round2/candidates/` in the workspace; their location was not looked for | not checked | NOT_RUN |
| R0.6 package `round2/submission_ready/` (workspace) | `sha256sum -c SHA256SUMS` | 13 files OK | VERIFIED |
| R0.5 video `round2/demo_video/out/AegisLab_Prototype_Demo.mp4` | SHA-256 against its README record | `ca648ab6…b694c`, matches | VERIFIED |
| `submission/` directory | does not exist in the repository or workspace root; nothing created or overwritten | — | VERIFIED |

## Security properties re-checked on the merged code

| Property | Evidence | Status |
|---|---|---|
| Role tokens never reach the browser; session cookie HttpOnly, SameSite=Strict; launch link single-use | live browser test `test_judge_flow_desktop` (asserts cookie flags, `document.cookie`, code reuse 403) on `7434152` and on the R4 branch | VERIFIED |
| Writes need session + CSRF + same origin | same test, step 10 (no CSRF 403, cross-origin 403, no cookie 403) | VERIFIED |
| Prohibited access denied by policy, not by error | prohibited-access scenario: 3 × HTTP 403 with `policy.denied` entries #26 to #28, run still SEALED, 0 of 18 protected markers in responses | VERIFIED (recorded run) |
| Sandbox permissions | `pytest -m podman` (13 passed), `security_demo.sh` 34/34 + 1 documented limit, sandbox-containment scenario in the live browser test | VERIFIED |
| Strict evidence verification of the recorded run | `verify_cli` with pinned key, release-recorded terminal hash `sha256:c85a3753…c3a4`, retained anchor: exit 0, 29 entries, 7 checkpoints | VERIFIED |
| Tamper rejection | disposable copy with one field added to entry 11: exit 1, `chain_ok: false`; original byte-identical afterwards (`sha256sum -c`) | VERIFIED |
| Clean shutdown | SIGINT to the launcher: exited, port 8400 closed, 0 `aegis-lab-*` containers | VERIFIED |
| R4 UI changes leak nothing | the three R4 changes are CSS only (`console.css`); no JavaScript, Python or API change; publication scan 0 FAIL 0 WARN | VERIFIED |
| No cloud-hosted privileged sandbox | nothing deployed; console binds 127.0.0.1 | VERIFIED |

## New R4 media (workspace `round2/final_prototype/`, not in the repository)

| Check | Result | Status |
|---|---|---|
| Secret exposure during recording | DOM and text compared at 12 points with launch code, CSRF token, session cookie, private-key and role-token strings, the run's canary (full and hex), local paths: 0 hits | VERIFIED |
| Address bar / terminal on screen | not captured (page-viewport screencast); the launch link is never displayed | VERIFIED |
| OCR of rendered frames | no OCR tool on the host | NOT_RUN |
| Kept evidence bundle | no token, private key, canary or local path | VERIFIED |
| Video decodes; audio; captions | 4,152 / 4,152 frames, 0 errors; AAC, no clipping; 0 s of speech outside captions | VERIFIED |
| Human watch-and-listen | — | HUMAN_APPROVAL_REQUIRED |
| `SHA256SUMS` over 1,309 files | `sha256sum -c` OK | VERIFIED |

## Not committed

No runtime state (`var/`), virtualenvs, model weights, recording frames or video files are in the R4 commits; `.gitignore`
(root and `aegislab/`) covers `var/`, `.venv/`, `.venv-browser/`, `*.pem`, `**/keys/`, `tokens.json` and model weights, and the
publication scan of the index passes.
