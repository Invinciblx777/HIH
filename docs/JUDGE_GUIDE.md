# Judge guide: five demonstrations in about ten minutes

Everything runs on one Linux machine with rootless Podman, offline after the first setup, with no GPU, model download or API key. Commands run from `aegislab/`.

```bash
git clone https://github.com/Invinciblx777/HIH.git
cd HIH/aegislab
bash scripts/quickstart.sh     # first time only: about 1-2 minutes; ends with one PASS line per stage
bash scripts/judge_demo.sh     # a few seconds; --pause waits for Enter between steps
```

## Result labels

The demos print a label wherever a result is not produced live on your machine.

| Label | Meaning |
|---|---|
| `[PASS]` / `[FAIL]` | Checked **live**, now, on this machine (real rootless containers, deterministic stub model) |
| `[PRECOMPUTED]` | From saved real-model runs in `evidence/phase3_2026-10-23/llm/`; the figures are recomputed from the raw observation files on screen, but **no model runs** during the demo |
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

`judge_demo.sh` step 6. Model Qwen2.5-0.5B-Instruct Q4_K_M on CPU llama.cpp, loopback only. Expected lines include `0 of 1040 isolation trials leaked (0 of 104 sessions)`, positive controls `16 of 16` and `13 of 16` sessions, pipeline `0 of 26 isolation runs`, and `[PASS] saved LLM runs agree with their raw observations, hashes and source files: 48 checks`. That last check is live: it recomputes the figures from the raw files and compares source-file hashes. The model runs themselves are saved, not live.

Re-running them is possible but slow and needs assets that are not in the repository: a local llama.cpp `llama-server` binary and the GGUF file, then `evaluation/llm_isolation.py` (about 3.5 hours on CPU). See `evidence/phase3_2026-10-23/README.md`.

## The longer demonstration and the numbers

```bash
bash scripts/security_demo.sh            # 34 checks plus 1 documented [LIMIT]
.venv/bin/python evaluation/check_claims.py         # recomputes every quoted figure from raw files
.venv/bin/python evaluation/check_presentation.py   # deck, notes, captions, Q&A against the claim matrix and raw evidence
```

## If the live run cannot be done

`evidence/phase4_2026-10-23/judge_demo_transcript.txt` is the output of a real successful execution on 23 Oct 2026. Present it as a **recording**, not as a live run.

## Where the guarantees stop

`judge_demo.sh` step 7 and `THREAT_MODEL.md`: trusted broker and signing key, shared host kernel, global role tokens, one small CPU model and ten probe wordings, base64 re-encoding not detected, timing padding weakens one classifier only, GPU and accelerator KV-cache isolation untested.
