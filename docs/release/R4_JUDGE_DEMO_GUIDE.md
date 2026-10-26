# R4 judge demonstration guide (3 to 5 minutes)

Team Tech Mavericks · Hack in Hills '26 · Track 04 (Bayora). Written in Phase R4 (26 October 2026) from a real run of the
merged prototype, public `main` = `7434152`. Every expected result below is what that run showed; the run ID, entry
numbers and times will differ slightly on another machine, the outcomes must not.

Labels the console uses, and what they mean:

| Label | Meaning |
|---|---|
| `LIVE SANDBOX · STUB MODEL` | A real run in rootless Podman containers. The model is the deterministic stub, not an LLM. |
| `LIVE SYSTEM TEST` | A real request to the control plane, or a real verifier process, started by the click. |
| `PRECOMPUTED REAL-MODEL` | Saved Qwen2.5-0.5B results. No model runs in the console. |
| `REPLAY · RECORDED` | A saved transcript, shown only when live execution is impossible. |
| `UNAVAILABLE` | The capability is missing on this machine; the reason is shown. |

## Before the judge arrives (2 minutes, off screen)

```bash
git clone https://github.com/Invinciblx777/HIH && cd HIH/aegislab
bash scripts/start_prototype.sh --reset      # prints "Mode: LIVE" and a one-time launch link
```

Needs Linux, Python 3.11 or newer and rootless Podman (the first start builds the sandbox image). Keep the terminal with
the launch link off the shared screen. Open `http://127.0.0.1:8400` (use `127.0.0.1`, not `localhost`). Without Podman the
console starts in degraded mode: do experiences 1, 4 (with the shipped bundles DEMO-001 and VAL-001), 5 and 6, and say so.

## Experience 1 · Security overview (40 s) · static architecture

Open **Connections** (topology). Header shows **Read-only · open the launch link**.

Say: *The red-team workload (attack agent, untrusted) and the blue-team workload (defence runner, frozen config) each run
in their own rootless container with no network. The client model, the model worker under test, is a third container. None
of them can reach another. The trusted broker is the only path between them: it checks attack commitments, applies timing
padding, seals results and writes the hash-chained audit log, signed with an Ed25519 key. The control plane enforces who
may do what; the evidence verifier is a separate program anyone can run.*

Select **Trusted broker**: the side panel says it is TRUSTED and that a compromised broker could sign a false but
consistent record. Do not claim otherwise. Solid lines are the only paths that exist; dashed red lines are paths the
system refuses.

## Experience 2 · Create an evaluation (60 s) · LIVE

1. Open the launch link in this browser. Header: **Operator session · roles act server-side**; page **Lab**.
   Say: *a single-use code was exchanged for an HttpOnly cookie; the browser never holds a role token.*
2. *Step 1 · Create a run*: Timing padding **none (faster)**, Defence profile **Hardened defence**, **Create run**.
   `LAB-001` appears with state CREATED. *Last step* shows the real calls with HTTP 200.
3. **Freeze configuration** → FROZEN (digests fixed under a signed checkpoint).
4. **Start the run** → RUNNING (`0 of 10 attacks evaluated`, last audit event) → **SEALED** in about 2 to 5 s:
   `10 of 10 evaluated · complete`, `signed up to #25`.

Point at the run ID `LAB-001` in the run box.

## Experience 3 · Demonstrate enforcement (60 s) · LIVE

**Unauthorised.** Scroll to *Scenarios*, open **Prohibited access to sealed results**, press **Run scenario on LAB-001**.
Expect **PASS** with three rows:

| Request | Result | Audit |
|---|---|---|
| `red_participant GET /api/runs/LAB-001/artifacts` | DENIED, HTTP 403, "attack artifacts are sealed until an authorised reviewer releases them" | entry #26 `policy.denied`, covered by a signed checkpoint |
| `red_participant POST /api/runs/LAB-001/release` | DENIED, HTTP 403, "only an authorised reviewer can release results" | entry #27 |
| `observer (no token) GET /api/runs/LAB-001/artifacts` | DENIED, HTTP 403 | entry #28 |

Checks: run still SEALED; 0 of 18 protected markers (canary, payloads, model outputs, tokens, key header) in any response.
Say: *the verdict is judged on the policy decision, the audit entry and the run state, not on HTTP success. A 403 here is
the security decision; a crash or a 500 would be reported as a failure, not a pass.*

**Authorised.** Back on **Lab**, press **Release as the reviewer** and confirm. State **RELEASED**, outcomes
`blocked_input 8 · safe_output 2`, the log closed by a signed terminal checkpoint.

Optional: **Audit → Signed audit log**, Decision = *denied*: 8 entries (the three above plus the broker's denials of
forbidden red mailbox requests during the run), each `signed`.

## Experience 4 · Verify audit integrity (45 s) · LIVE

**Evidence → LAB-001 (this console, live run)**:

1. **Verify with the independent verifier** → *Accepted · exit 0 · as expected*. A separate `python -m aegis.verify_cli`
   process, broker key pinned, terminal hash recorded at release.
2. *Tamper with a disposable copy*: choose *Change one recorded event: add a field to audit entry 11*, **Tamper and
   verify** → **PASS**: tampered copy *exit 1, rejected* ("entry content does not match its hash"); original *exit 0,
   accepted*, byte-identical before and after, copy deleted.

## Experience 5 · Research evidence (30 s) · PRECOMPUTED

Open **Experiments**. Say: *these are PRECOMPUTED REAL-MODEL results from saved runs of Qwen2.5-0.5B-Instruct on CPU
(llama.cpp). Nothing reruns here. The console recomputes every figure from the raw files and shows how many checks agree.
The live run you just watched used the deterministic stub model inside the real sandbox controls.* Read the caveat: zero
observed leaks bound a rate for this configuration; they do not prove isolation.

## Experience 6 · Limitations (30 s)

Open **Threat Model** (*Tested in the demonstrated environment* vs *Not proven or not addressed*). Say plainly:

- The broker and its signing key are trusted. A compromised broker or a stolen key can produce a false but consistent
  record; only the terminal hash the reviewer wrote down at release detects a full re-signed rewrite.
- One trusted local operator drives every role through the console. This is not multi-user authentication.
- All containers share the host kernel; kernel or runtime escapes were not attempted.
- Side channels remain: padding weakens one timing classifier; cache and memory-bandwidth channels are not measured.
- GPU and accelerator KV-cache isolation was not tested; the real-model runs were CPU only.
- The real-model experiments use one small model; they bound what was observed, not what a larger model would do.

## Close

Press **End session** (header returns to **Read-only**), then Ctrl-C in the terminal. The launcher removes any
`aegis-lab-*` container (`podman ps -a --filter label=aegislab=1` shows none).

## If something goes wrong

| Symptom | Meaning / action |
|---|---|
| `invalid or already used launch code` | Each link works once. `bash scripts/start_prototype.sh --link` in a second terminal prints a new one. |
| Buttons disabled with "Read-only" | No operator session in this browser. Open a new launch link. |
| `Mode: degraded` at start | Podman missing or not rootless. Live scenarios are off and say UNAVAILABLE; evidence verification still works. |
| Scenario says *Needs a SEALED run* | The run was already released. Create a new run (it becomes `LAB-002`). |
| A scenario shows FAIL or ERROR | Do not explain it away. It is a real finding; note the run ID and the audit entry. |

The recorded version of this walkthrough (138 s, from `7434152`) is described in the team workspace under
`round2/final_prototype/` (not in this repository).
