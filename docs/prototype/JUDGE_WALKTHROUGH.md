# Judge walkthrough: AegisLab prototype console (about 5 minutes)

This walkthrough needs Linux with rootless Podman and Python 3.11 or newer. Without Podman, follow steps 1, 5, 6 and 7: the console runs in degraded mode and shows a recorded execution instead of live runs. It labels that recording clearly.

## 1. Start (30 s)

```bash
cd HIH/aegislab
bash scripts/start_prototype.sh --reset
```

Open **http://127.0.0.1:8400**. The status strip at the top should read `Containers Podman … rootless` and `Model STUB MODEL`, and the rail should show **Live mode**. The Overview page verifies the shipped DEMO-001 bundle on load.

## 2. See the boundaries (30 s)

Open **Isolation topology** and select **Trusted broker**. This is the only path between the sandboxes. The page says plainly that the broker is trusted and that everything shares one Linux kernel; nothing here is hardware isolation. Select **Red-team sandbox** to see its exact `podman run` hardening flags, read live from the code.

## 3. Start a live run (15 s)

Open **Attack lab** and press **Start a live run**. `LAB-001` moves through CREATED, FROZEN, RUNNING and SEALED in real rootless containers, in about 5 seconds.

## 4. Attack it (2 min)

Run the scenarios in this order:

1. **Prohibited access to sealed results.** Red tries to read the sealed results and to release them; an anonymous caller tries to read them. Expect **PASS**: three HTTP 403 refusals, each with its `policy.denied` audit entry (sequence number, hash, covered by a signed checkpoint). The run is still SEALED, and no protected value appears in any response.
2. **Cross-role isolation.** Blue is refused red's payloads and does not see the secret digests that the reviewer sees. A forged token gets 401. The five forbidden requests that the red sandbox itself sent during the run are listed as broker denials.
3. **Sandbox containment.** A probe container with red's hardening flags tries the network, DNS, a root-filesystem write and foreign paths. It also plants a symlink and a FIFO in its mailbox. Every attempt is refused or harmless, CapEff is 0, and the broker's replies land as regular files.
4. **Authorised release.** Press it, then **Confirm release of LAB-001** within 8 seconds. The reviewer is the one role allowed to release. Expect HTTP 200, `run.released`, strict verification with a terminal checkpoint, and 10 of 10 commitments verified.

Under **Try a request yourself**, you can send one request as any role. For example, `blue_participant` reading the artifacts of a SEALED run gets 403.

## 5. Watch the record (20 s)

Open **Security events**. Every refusal above is in the redacted stream. It shows who did what, the decision and whether a signed checkpoint covers it, but never a payload or model output. Filter by **Decision: denied**.

## 6. Verify and break the evidence (1 min)

Open **Evidence verification**:

1. Select **LAB-001 (this console, live run)** and press **Verify with the independent verifier**. Expect exit 0. This is a separate `python -m aegis.verify_cli` process with the broker key pinned.
2. Under **Tamper with a disposable copy**, choose **Rewrite an attack outcome and recompute every later hash** and press **Tamper and verify**. Expect **PASS**: the copy is rejected (exit 1, with the verifier's findings shown), the original is still accepted, it is byte-identical before and after, and the copy is deleted.
3. Select **VAL-001 TAMPERED example**. It fails, as it must.

## 7. Read the claims and their limits (1 min)

Open **Experiment results**. The real-model numbers (Qwen2.5-0.5B, CPU) are **PRECOMPUTED REAL-MODEL EVIDENCE**; no model runs here. The page recomputes them from the raw files: *48 of 48 checks agree*.

Read the boxed caveat. Zero observed leaks bound a rate for this configuration; they do not prove isolation. GPU and accelerator KV-cache isolation were not tested.

**Threat model and limits** lists what is not addressed, including:

- a compromised broker;
- a stolen signing key;
- re-encoded canaries;
- timing channels beyond one classifier.

## Stop

Press Ctrl-C in the terminal. The launcher removes any lab containers. The state is in `aegislab/var/console/`; delete it, or start with `--reset`.

## If something differs

- **The rail shows Degraded mode.** The reason is printed in the terminal and on the Overview page. Steps 5 to 7 still work on the shipped bundles. The Attack lab shows the recorded 23 Oct judge-demo transcript, labelled RECORDED EXECUTION (not live).
- **A scenario says it "needs a SEALED run".** Start a new run. Scenarios never run against a RELEASED run.
