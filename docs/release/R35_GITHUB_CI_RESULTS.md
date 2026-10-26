# Phase R3.5 GitHub Actions results

Workflow: `.github/workflows/release-gates.yml` (job `gates`, `ubuntu-24.04`, Python 3.14). It runs
`aegislab/scripts/release_gates.sh --with-browser --strict`, the same script that ran locally.

## Before this phase

On 26 October 2026, before any R3 push, `gh run list` for `Invinciblx777/HIH` returned **no workflow runs at all**:
the workflow had never executed on GitHub. Repository Actions settings: enabled, all actions allowed.

## Hosted run

The branch was pushed with the team's approval on 26 October 2026 and pull request #5 was opened. These are the first
workflow runs in the repository's history. Both ran on the reviewed commit `52db77d2ccf390e5af73e86bc56e8654d1e8eec7`.

| Field | Pull-request run | Push run |
|---|---|---|
| Workflow URL | https://github.com/Invinciblx777/HIH/actions/runs/40329363729 | https://github.com/Invinciblx777/HIH/actions/runs/40329309774 |
| Run ID | 40329363729 (job 121594358112) | 40329309774 (job 121594165574) |
| Event / branch | `pull_request`, PR #5, `r3/security-hardening` into `main` | `push`, `r3/security-hardening` |
| Commit SHA | `52db77d` | `52db77d` |
| Time (UTC) | 13:17:55 to 13:26:16 | 13:17:32 to 13:30:51 |
| Step outcomes | all `success`: checkout (SHA-pinned), setup-python (SHA-pinned), console virtualenv, browser virtualenv + Chromium, release gates, keep the gate logs | same, all `success` |
| Artifact | `release-gate-logs` (id 12654262098) | `release-gate-logs` (id 12655067863) |
| Conclusion | **success** | **success** |

Gate summary from the pull-request run's artifact (`summary.txt`), identical in shape to the local run:

```
PASS     python-syntax          exit 0    1s  50 files parsed; aegis.console imports
PASS     js-syntax              exit 0    1s
PASS     pytest-container-free  exit 0   72s  449 passed, 2 skipped, 14 deselected, 2 warnings in 71.43s (0:01:11)
PASS     check-claims           exit 0    2s
PASS     check-presentation     exit 0    1s  157/157 presentation checks pass
PASS     manifest               exit 0    1s  MANIFEST.sha256: 259 entries OK
PASS     publication-scan       exit 0    7s  result: 0 FAIL, 0 WARN
PASS     browser-core           exit 0   18s  verdict: PASS
summary: 0 failed, 0 skipped
```

Skips, stated exactly: in `pytest-container-free` the 2 skips are the two browser modules, because Playwright is not
installed in `.venv` by design (`SKIPPED (dependency missing)`). The container-free one of them runs in the
`browser-core` gate through `.venv-browser`: 6 PASS, 0 FAIL, 0 SKIPPED, 0 BLOCKED. The live one needs Podman and the
sandbox image and is not run by CI (see below). The 14 deselected tests are the 13 marked `podman` and P4D01.

A later commit on the same branch that only records these results triggers new runs. Their outcome is visible on PR #5.
This file does not claim it in advance.

### Run on the merge commit (recorded in Phase R4)

PR #5 was merged on 26 Oct 2026 at 17:38:12 UTC. The `push` to `main` started run
https://github.com/Invinciblx777/HIH/actions/runs/40370478665 (job 121739547574) on `743415223e916d31c43c48f648d31524c8ba1d88`,
17:38:15 to 17:41:04 UTC, conclusion **success**. Its artifact `release-gate-logs` (id 12673006726) has the same summary
shape: 8 gates PASS, `summary: 0 failed, 0 skipped`, pytest-container-free `449 passed, 2 skipped, 14 deselected`.
The record commit `1cdca1b` (this text, first version) was never pushed; R4 re-applied it on top of `main`.

## What hosted CI can and cannot prove

It can prove, on a clean GitHub runner: dependencies install from the pinned constraints; Python and JavaScript parse;
the 449 container-free tests; the claims, presentation, manifest and publication gates; and 6 browser tests against a real
console process in degraded mode with real Chromium and the real verifier.

It does not prove anything that needs rootless Podman and the sandbox image: `pytest -m podman`, `judge_demo.sh`,
`security_demo.sh`, the live browser lifecycle. Those are recorded from the supported Fedora host in
`PHASE_R35_RELEASE_REPORT.md`.
