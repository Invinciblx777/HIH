# Judge guide: five demonstrations in about ten minutes

Everything runs on one Linux machine with rootless Podman, offline after the first setup, with no GPU, model download or API key. Commands run from `aegislab/`.

```bash
git clone https://github.com/Invinciblx777/HIH.git
cd HIH/aegislab
bash scripts/quickstart.sh     # first time only: about 1-2 minutes; ends with one PASS line per stage
bash scripts/judge_demo.sh     # a few seconds; --pause waits for Enter between steps
```

## No Linux machine at hand? The public read-only demo

RENDER_URL is the prototype console in read-only mode (`AEGIS_PUBLIC_DEMO=1`), hosted on Render. On Render's free plan, if it has been idle for 15 minutes, the first page load takes about a minute while the service wakes. A secondary copy at https://aegislab.vercel.app may lag behind the code in this repository. You can:

- browse every page (lab, connections, audit, evidence, experiments, threat model);
- play the recorded replay of a real `judge_demo.sh` execution (labelled RECORDED);
- open **Evidence**, pick a bundle and click **Verify with the independent verifier**. This runs the real `aegis.verify_cli` as a separate process on the server: genuine bundles are accepted, and the tampered and legacy examples are rejected;
- tamper with a disposable copy of a genuine bundle and watch the verifier reject the copy while the original still verifies.

It cannot run anything live. There are no containers, no operator session and no launch link. Every other state-changing request returns HTTP 403, and verifier requests are rate-limited (HTTP 429). The demonstrations below need the local setup: a Linux machine with rootless Podman. The live console stays loopback-only and is never hosted.

## Result labels

The demos print a label wherever a result is not produced live on your machine.

| Label | Meaning |
|---|---|
| `[PASS]` / `[FAIL]` | Checked **live**, now, on this machine (real rootless containers, deterministic stub model) |
| `[PRECOMPUTED]` | From saved real-model runs: the newest set, `evidence/finale_p4_2026-11-11/llm_final/` (re-measured 11 Nov 2026 on the finale P4 code), else `evidence/finale_p3_2026-11-10/llm/` (10 Nov), else the 23 Oct set `evidence/phase3_2026-10-23/llm/`. The figures are recomputed from the raw observation files on screen, but **no model runs** during the demo |
| `LIVE REAL MODEL` | `scripts/real_model_demo.sh` and the real-model console: the model answers now, on this machine (section 6) |
| `[HISTORICAL]` | A recorded result of an older version (for example the Phase 1 broker before a fix); not re-run |
| `[LIMIT]` (security demo) | A documented limitation, demonstrated on purpose |
| `NOT RUN` | A check could not run in this tree; the line says why |

## 1. A prohibited cross-boundary attempt is rejected (LIVE)

`judge_demo.sh` steps 2 and 3. Look for:

- `denied: red participant reads sealed artifacts: HTTP 403`, `denied: red participant releases the run: HTTP 403`, `denied: reviewer reads artifacts before release: HTTP 403`, `denied: forged identity token: HTTP 401`.
- `the red sandbox's forbidden requests were denied by the broker and logged: 5 logged` (the denials are audit events).
- The hostile-mailbox attack: a real rootless container plants a symlink and a FIFO at the broker's temp names. Expected: replies delivered as regular files, the victim file intact, nothing created outside the mailbox, the broker not blocked.

## 2. A legitimate, authorised operation succeeds (LIVE)

`judge_demo.sh` step 2 and step 4: the operator freezes and starts run `JD-1`, the run reaches `SEALED`, the reviewer releases it (`SEALED -> RELEASED: HTTP 200`).

## 3. An authentic sealed evidence bundle passes strict verification (LIVE)

`judge_demo.sh` step 4: `ok True`, `terminal_verified True`, `key_source pinned (--pubkey)`, exit 0. To check the shipped bundles yourself:

```bash
.venv/bin/python -m aegis.verify_cli --bundle evidence/closeout_2026-10-22/DEMO-001_released --run-id DEMO-001 --expect-state RELEASED   # exit 0
.venv/bin/python -m aegis.verify_cli --bundle var/quickstart/bundles/DEMO-001 --run-id DEMO-001 --expect-state RELEASED                  # exit 0, the bundle quickstart just produced
```

## 4. A modified copy is rejected (LIVE)

`judge_demo.sh` step 5: three entries removed from a copy, `ok False`, findings `... truncation`, exit 1; the original still verifies. Try your own edit:

```bash
rm -rf /tmp/tampered && cp -a var/quickstart/bundles/DEMO-001 /tmp/tampered
.venv/bin/python - <<'PY'
import json; p = "/tmp/tampered/audit.jsonl"; L = open(p).read().splitlines()
e = json.loads(L[10]); e["data"] = dict(e.get("data", {}), tampered=True); L[10] = json.dumps(e)   # change one recorded event
open(p, "w").write("\n".join(L) + "\n")
PY
.venv/bin/python -m aegis.verify_cli --bundle /tmp/tampered --run-id DEMO-001 --expect-state RELEASED; echo "exit $?"   # expect exit 1
```

A shipped tampered example must also fail: `evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3` (exit 1).

## 5. Real-model evidence, next to controls that must leak (PRECOMPUTED)

`judge_demo.sh` step 6. Model Qwen2.5-0.5B-Instruct Q4_K_M on CPU llama.cpp, loopback only. Expected lines include `0 of 1040 isolation trials leaked (0 of 104 sessions)`, positive controls `16 of 16` and `13 of 16` sessions, pipeline `0 of 26 isolation runs`, and `[PASS] saved LLM runs agree with their raw observations, hashes and source files: 89 checks` (48 before the 10 Nov re-measurement). That last check is live: it recomputes the figures from the raw files and compares source-file hashes. The model runs themselves are saved, not live.

The step prints where and when the figures were recorded. Since 11 Nov 2026 that is the re-measurement on the finale P4 code (`evidence/finale_p4_2026-11-11/`), with the same E1 figures as 10 Nov and 23 Oct. Re-running the experiments needs assets that are not in the repository: a local llama.cpp `llama-server` binary and the GGUF file, then `evaluation/llm_isolation.py` (33 minutes on 11 Nov). See `evidence/finale_p4_2026-11-11/README.md`.

## 6. The real model, live (optional; needs the model files)

If `llama-server` (llama.cpp b11819, CPU) and `qwen2.5-0.5b-instruct-q4_k_m.gguf` are on the machine (default `../../../_models/` from `aegislab/`, or `AEGIS_MODELS_DIR`):

```bash
bash scripts/real_model_demo.sh          # about 30 s, offline; header and footer say LIVE REAL MODEL
```

One `PASS`/`FAIL` line per check, under four headings:

- **(a)** independent sessions are stateless: no session recovers another one's canary, and the server reports 0 cached prompt tokens;
- **(b)** a positive control that deliberately shares history does leak, so the probe can see a leak;
- **(c)** the same leak sent through the full pipeline is withheld by the broker, with a `canary.leak` audit entry;
- **(d)** the run's exported bundle verifies strictly, and a tampered copy is rejected.

The model server runs in rootless Podman with `--network none` and is reached over a UNIX socket. The script refuses to start if either file's sha256 differs from the one the evidence was recorded with. Nothing falls back to the stub.

For the console with the real model: `bash scripts/start_real_model_console.sh` (port 8410), then open the launch link. Every run shows "REAL MODEL · LIVE", the model file, its sha256 prefix, "llama.cpp CPU" and "loopback".

## The longer demonstration and the numbers

```bash
bash scripts/security_demo.sh            # 34 checks plus 1 documented [LIMIT]
.venv/bin/python evaluation/check_claims.py         # recomputes every quoted figure from raw files
.venv/bin/python evaluation/check_presentation.py   # deck, notes, captions, Q&A against the claim matrix and raw evidence
```

## If the live run cannot be done

`evidence/phase4_2026-10-23/judge_demo_transcript.txt` is the output of a real successful execution on 23 Oct 2026. Present it as a **recording**, not as a live run.

## Where the guarantees stop

`judge_demo.sh` step 7 and `THREAT_MODEL.md`: trusted broker and signing key (a reviewer countersignature helps only with the reviewer key off the host), shared host kernel (containers no longer run as the key owner), one small CPU model and ten probe wordings, double-encoded or paraphrased canaries not detected, 250 ms padding leaks with a real model (deadline release is the real-model default), GPU and accelerator KV-cache isolation untested.
