# Phase R3.5 GitHub Actions results

Workflow: `.github/workflows/release-gates.yml` (job `gates`, `ubuntu-24.04`, Python 3.14). It runs
`aegislab/scripts/release_gates.sh --with-browser --strict`, the same script that ran locally.

## Before this phase

On 26 October 2026, before any R3 push, `gh run list` for `Invinciblx777/HIH` returned **no workflow runs at all**:
the workflow had never executed on GitHub. Repository Actions settings: enabled, all actions allowed.

## Hosted run

| Field | Value |
|---|---|
| Status | PENDING_APPROVAL (the branch is not pushed yet) |
| Workflow URL | NOT_RUN |
| Run ID | NOT_RUN |
| Branch | NOT_RUN |
| Commit SHA | NOT_RUN |
| Step outcomes | NOT_RUN |
| Skipped checks | NOT_RUN |
| Artifact | NOT_RUN |
| Conclusion | NOT_RUN |

## What hosted CI can and cannot prove

It can prove, on a clean GitHub runner: dependencies install from the pinned constraints; Python and JavaScript parse;
the 449 container-free tests; the claims, presentation, manifest and publication gates; and 6 browser tests against a real
console process in degraded mode with real Chromium and the real verifier.

It does not prove anything that needs rootless Podman and the sandbox image: `pytest -m podman`, `judge_demo.sh`,
`security_demo.sh`, the live browser lifecycle. Those are recorded from the supported Fedora host in
`PHASE_R35_RELEASE_REPORT.md`.
