# R3 judge release checklist

For the AegisLab console release candidate built in Phase R3 (branch `r3/security-hardening`). Each line is a command
with the result it must give. Run from `HIH/aegislab/` on the supported host: Fedora with rootless Podman 5.x and
Python 3.11 or newer. A check that cannot run is recorded as SKIPPED or BLOCKED with the reason, never as passed.

## A. Container-free gates (any Linux host; also what CI runs)

| # | Command | Must give |
|---|---|---|
| A1 | `bash scripts/release_gates.sh --with-browser --strict` | `summary: 0 failed, 0 skipped`, exit 0 |

It covers: Python syntax and imports, `node --check` of the console script, `pytest -m "not podman"`,
`evaluation/check_claims.py`, `evaluation/check_presentation.py`, `sha256sum -c MANIFEST.sha256`,
`tools/publication_scan.py`, and the container-free browser tests (`scripts/run_browser_tests.sh --require`).
The same script runs in `.github/workflows/release-gates.yml`.

## B. Integration gate (needs rootless Podman and the sandbox image)

| # | Command | Must give |
|---|---|---|
| B1 | `bash scripts/start_prototype.sh --check` | `ok` lines and `Mode: LIVE` |
| B2 | `.venv/bin/python -m pytest -q -rs` | all passed; the only skips are the two browser modules (`SKIPPED (dependency missing)`, Playwright is not in `.venv` by design) |
| B3 | `.venv/bin/python -m pytest -q -m podman` | all passed (same two browser skips) |
| B4 | `bash scripts/judge_demo.sh` | `17/17 checks behaved as expected` |
| B5 | `bash scripts/security_demo.sh` | `34/34 checks behaved as expected` plus the 1 documented limit |
| B6 | `bash scripts/run_browser_tests.sh --all --require` | `verdict: PASS`, 9 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED |
| B7 | `git status --short` | empty (the gates write nothing into the tree except `docs/prototype/screenshots/r3/`, which they regenerate) |

## C. Clean checkout and launch

| # | Step | Must give |
|---|---|---|
| C1 | `git clone <repo> && cd HIH/aegislab && bash scripts/start_prototype.sh --reset` | creates `.venv`, builds the image, prints `Mode: LIVE` and a launch link |
| C2 | open `http://127.0.0.1:8400` | header **Read-only**; every write control disabled with the reason |
| C3 | open the printed launch link | header **Operator session · roles act server-side**, page **Lab** |
| C4 | open the same link again (another browser or history) | `invalid or already used launch code` (403) |
| C5 | `bash scripts/start_prototype.sh --link` in a second terminal | a new link that works once |
| C6 | Ctrl-C | console stops; `podman ps -a --filter label=aegislab=1` shows no `aegis-lab-*` container |

## D. The 3 to 5 minute demonstration (live)

Follow `docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`. Expected, in order:

1. Create `LAB-001` (no padding, hardened profile) → CREATED, two real calls with HTTP 200.
2. Freeze → FROZEN. Start → RUNNING → SEALED in about 5 s, 10 of 10 attacks evaluated.
3. Prohibited access → PASS: 3 × DENIED (403), each with a `policy.denied` audit entry.
4. Cross-role isolation → PASS: blue refused, digests hidden, forged token 401, 5 broker denials.
5. Release as the reviewer (confirm) → RELEASED, outcomes shown, terminal checkpoint hash.
6. Signed audit log → the refusals with sequence numbers and `signed`.
7. Evidence → LAB-001 verifies (exit 0, as expected); a tampered disposable copy is rejected (exit 1); original
   byte-identical; in-memory suite 12 of 12.
8. Probe: observer → release on the released run → 403, *recorded after the signed chain closed (unsigned)*.
9. **End session** → Read-only.

Say aloud: the model is the deterministic **stub**, not an LLM; real-model numbers are **precomputed**; the session is
**one local operator**, not multi-user authentication.

## E. Before publication (human decisions)

| # | Item |
|---|---|
| E1 | Review the diff `git diff 209d386..r3/security-hardening` and `docs/prototype/R3_SECURITY_REVIEW.md` |
| E2 | Approve pushing `r3/security-hardening`; the first GitHub Actions run of `release-gates` must be green before merging |
| E3 | Approve the merge into `main` (PR), then re-run A1 and B2–B6 on the merge commit |
| E4 | Decide whether to tag the release candidate (`aegislab-r3-rc1` exists only locally) |
| E5 | Unchanged by R3 and still the team's call: the deck, video and submission files on Unstop |

## F. Must stay unchanged

- `MANIFEST.sha256`: all 259 entries verify (`sha256sum -c`); no pinned file was edited.
- Historical evidence under `aegislab/evidence/` and the R2 screenshots in `docs/prototype/screenshots/r2/`.
- rc1 to rc4 candidates (outside this repository) were not touched.
