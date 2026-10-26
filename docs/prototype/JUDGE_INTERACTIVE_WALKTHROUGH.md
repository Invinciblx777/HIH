# Judge interactive walkthrough (Phase R2, 3 to 5 minutes)

This is a click path through the AegisLab console. Every step says whether what you see is **live** (it happens now, on
your machine, in real rootless containers) or **saved** (it was recorded earlier and is only displayed).

| Label in the console | Meaning |
|---|---|
| `LIVE SANDBOX · STUB MODEL` | A real run in rootless Podman containers. The "model" is the deterministic stub, not an LLM. |
| `LIVE SYSTEM TEST` | A real request to the control plane, or a real verifier process, started by your click. |
| `REPLAY · RECORDED` | A saved transcript, shown only when live execution is impossible. |
| `PRECOMPUTED REAL-MODEL` | Saved results of the Qwen2.5-0.5B experiments. No model runs in the console. |
| `UNAVAILABLE` | The capability is missing on this machine (for example, no Podman); the reason is shown. |

Needs Linux with rootless Podman and Python 3.11 or newer. Without Podman, do steps 1, 6 and 8 only.

## 1. Start the console (30 s) · live

```bash
cd HIH/aegislab
bash scripts/start_prototype.sh --reset
```

The launcher prints a launch link, `http://127.0.0.1:8400/session/start?code=…`. First open **http://127.0.0.1:8400**
without the code: the header says **Read-only**, and every button that would change state is disabled with the reason.
Now open the launch link. The header changes to **Operator session · roles act server-side**, and you land on **Lab**.

What this shows: the browser never holds a role token. The link exchanged a one-time code for an HttpOnly session
cookie. Each role's request is sent by the server, with that role's token, through the unchanged role checks. It is
one local operator driving demonstration roles, not multi-user authentication.

## 2. Create, configure, freeze and start a run (45 s) · live

On **Lab**, under *Step 1 · Create a run*:

1. Set **Timing padding** to *none (faster)* and **Defence profile** to *Hardened defence*. Press **Create run**.
   `LAB-001` appears only after the server confirms it. *Last step* lists the two real calls: `operator POST /api/runs`
   and `blue_participant POST /api/runs/LAB-001/defence-config`, both HTTP 200.
2. Press **Freeze configuration**. The state becomes FROZEN, and the digests of the defence config and attack pack are
   fixed under a signed checkpoint. The blue participant can no longer change the defence: a later submission is
   refused with 409, and the refusal is in the audit log.
3. Press **Start the run**. The run box shows RUNNING, the attacks evaluated so far and how far the audit log is
   signed. It reaches SEALED in about 5 seconds with the stub model.

## 3. Attack the result gate (60 s) · live

Open the **Prohibited access** card and press **Run scenario on LAB-001**. Expect **PASS**:

- three requests (red reads the sealed results, red tries to release, an anonymous caller reads) are each DENIED with
  HTTP 403;
- each refusal has its `policy.denied` audit entry, with sequence number, hash and signature status;
- the run is still SEALED, and no protected value (canary, payloads, model outputs, tokens) appears in any response.

Then open **Cross-role isolation** and run it. The blue participant is refused red's payloads and does not see the
digests the reviewer sees. A forged token gets 401. The five forbidden mailbox requests that the red sandbox sent
during the run are listed as broker denials.

Optional (live): under **Try a request yourself**, choose *Observer*, *Release the run* and press **Send request**.
You see the status and decision; the response itself stays on the server.

## 4. Release as the reviewer (20 s) · live

In the run box, press **Release as the reviewer** and confirm in the dialog. The run becomes RELEASED, with outcomes
such as `blocked_input 8 · safe_output 2` for the hardened profile. The result shows the terminal checkpoint hash.
Release is final: the run never returns to SEALED.

## 5. Read the signed audit log (20 s) · live

Follow **open** next to *Audit log* in the run box (or **Audit**, then **Signed audit log**). This is the run's
hash-chained audit log, entry by entry. Set **Decision** to *denied*: the refusals from step 3 are there with their
operation and reason. The meta line shows how far checkpoints sign the log and that the terminal anchor is written.
Payloads, model outputs, defence rules and the digests of team inputs never leave the server.

## 6. Verify the evidence and break a copy (60 s) · live

Open **Evidence** and select **LAB-001 (this console, live run)**:

1. Press **Verify with the independent verifier**. Expect exit 0 and *as expected*. This is a separate
   `python -m aegis.verify_cli` process with the broker key pinned and the terminal hash from the release.
2. Under **Tamper with a disposable copy**, choose a change (for example *Change one recorded event: add a field to audit entry 11*) and
   press **Tamper and verify**. Expect **PASS**: the copy is rejected (exit 1, with the verifier's finding), the
   original is accepted and byte-identical before and after.
3. Press **Run all 12** under the in-memory checks. Expect *12 of 12 in-memory modifications detected; stored log
   unchanged: yes*.

The shipped bundles DEMO-001 and VAL-001 are **saved** evidence from 22 October. Verifying them is live; the bundles
themselves are not new. *VAL-001 TAMPERED* must fail, and does.

## 7. See what you tested on the graph (20 s) · live marks on a static diagram

Open **Connections**. The diagram is the static architecture. The **Observed** chip overlays the scenarios you just ran:
a check mark on each edge whose expected outcome held. Select an edge's component to see the verdict, run, time and
audit sequence of the observation.

## 8. Read the claims and their limits (30 s) · saved

Open **Experiments**. The real-model figures (Qwen2.5-0.5B, CPU) are **PRECOMPUTED REAL-MODEL** results from saved runs;
nothing reruns here. The page recomputes each figure from the raw files and shows how many checks agree. Read the
caveat: zero observed leaks bound a rate for this configuration; they do not prove isolation. **Threat Model** lists
what is out of scope, including a compromised broker, a stolen signing key and GPU or accelerator cache isolation.

## Stop

Press Ctrl-C in the terminal. The launcher removes any lab containers. A run that was RUNNING when the console stopped
is marked FAILED with a signed terminal checkpoint the next time it starts.

Screenshots of each state, captured by the browser tests from a real run: `docs/prototype/screenshots/r2/`.
