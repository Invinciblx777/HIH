# Final judge checklist (Phase R3.5)

For a judge or reviewer starting from the public repository. Run on Linux with rootless Podman and cgroups v2 (tested on
Fedora with Podman 5.8.9 and Python 3.14). Everything runs on loopback; nothing is hosted.

## 1. Get the code (1 minute)

```bash
git clone https://github.com/Invinciblx777/HIH.git
cd HIH/aegislab
```

## 2. Offline judge demo (a few seconds after set-up)

```bash
bash scripts/quickstart.sh       # first time: venv, dependencies, sandbox image, test suite, demo run
bash scripts/judge_demo.sh       # must end: 17/17 checks behaved as expected
```

Results are labelled **LIVE** (real rootless containers, stub model), **PRECOMPUTED REAL-MODEL** (saved runs recomputed
from raw files) or **HISTORICAL** (recorded, labelled as such). No model runs during the demo.

## 3. Interactive console walkthrough (3–5 minutes)

```bash
bash scripts/start_prototype.sh  # prints a launch link; Ctrl-C stops the console and removes its containers
```

| Step | Do | Expect |
|---|---|---|
| 1 | Open `http://127.0.0.1:8400` | header **Read-only**; write controls disabled with the reason |
| 2 | Open the printed launch link | header **Operator session · roles act server-side**, page **Lab** |
| 3 | Open the same link again | `invalid or already used launch code` (each link works once) |
| 4 | Lab: **Create run**, then freeze and start | a `LAB-nnn` run moves `CREATED → FROZEN → RUNNING → SEALED` in real containers |
| 5 | Run the **Prohibited access to sealed results** scenario | red reading, red releasing and an anonymous read are each DENIED, with signed audit entries |
| 6 | **Release as the reviewer** | `RELEASED`; a signed bundle is exported |
| 7 | Evidence: verify the new bundle, then tamper with a copy | original **Accepted**; tampered copy **Rejected**; original digests unchanged |
| 8 | "Try a request yourself": observer releases the released run | **DENIED 403**, shown as recorded after the signed chain closed, **unsigned** |
| 9 | **End session** | back to read-only |

Step-by-step version with timings: `docs/prototype/JUDGE_INTERACTIVE_WALKTHROUGH.md`.
Need another link while the console runs: `bash scripts/start_prototype.sh --link`.
Without Podman the console starts in a labelled **degraded** mode: evidence verification works, live scenarios are off.

## 4. Verify the shipped evidence yourself

```bash
. .venv/bin/activate
python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released --run-id DEMO-001 --expect-state RELEASED   # exit 0
python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3 --run-id VAL-001 --expect-state RELEASED   # exit 1
python evaluation/check_claims.py
```

## 5. Limits to keep in mind

- One trusted local operator on loopback; not multi-user authentication. Never expose the console on a network.
- Cookies are not isolated by port on 127.0.0.1: use a dedicated browser profile.
- Refusals after release are kept unsigned (`post_terminal.jsonl`); the UI says so.
- Single Fedora host; containers share the host kernel; GPU isolation not tested; real-model figures are from saved runs.

Full list: `README.md` "Known limitations" and `docs/prototype/R3_SECURITY_REVIEW.md` section 6.
