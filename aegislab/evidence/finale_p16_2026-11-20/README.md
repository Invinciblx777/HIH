# Finale P16 evidence (20 Nov 2026): sponsor integrations, all OFF by default

Branch `finale/p16-sponsors`, cut from the tag `aegislab-finale` (c15fcaa). With the P16 variables unset (`AEGIS_GUARD_RUNDIR`,
`AEGIS_N8N_WEBHOOK`), nothing below is loaded and every run is the tag's. No file pinned by a saved experiment was changed
(check_claims source drift: aegis/runtime.py, runs.py, model_client.py, api.py, evidence.py, userns.py,
scripts/start_model_server.sh, sandbox/*, samples/*, Containerfile are byte-identical to the tag), and the sandbox image is
unchanged (the guard runner lives in `aegislab/guard/`, outside the image's `COPY sandbox/`).

## Part A: Qwen3Guard blue-team guard

Guard model: Qwen/Qwen3Guard-Gen-0.6B, revision fada3b2f655b89601929198343c94cd2f64d93cc (official weights), converted with
llama.cpp b11819's `convert_hf_to_gguf.py --outtype q8_0` -> `Qwen3Guard-Gen-0.6B-Q8_0.gguf`, sha256
3f66ce2417b6df317e750b4c5bd847cb8e3e120eb9b3314b347269d87223efcd (804753088 bytes). Not committed; provenance in
`_models/qwen3guard/PROVENANCE.txt` next to the file. Served by the pinned llama-server b11819 (qwen3 architecture loads).

Isolation (`scripts/start_guard_server.sh`): its own rootless Podman container (network none, read-only root, cap-drop ALL,
userns auto, uid 900 -> its own subordinate host UID), its own socket and key, read-only weights, never the client model's.
Only the defence runner's container gets the socket (`aegis/guard.py`); red and the model worker never do
(`tests/test_finale_p16_guard.py` P16A20 / P16A21, live).

| directory | what | how to re-run |
|---|---|---|
| `guard_eval/` | detection and false positives, regex vs qwen3guard vs both, 512 texts; latency per call | `evaluation/guard_eval.py --guard-rundir RUN --datasets DIR --out ...` |
| `timing_guard/exec1_seed20261120/` | timing classifier with the guard on (P4 protocol), unpadded vs deadline, 20 runs each | `AEGIS_GUARD_RUNDIR=RUN AEGIS_VAR=... evaluation/timing_guard.py --seed 20261120 --out-dir ...` |

Datasets (downloaded outside the repository at pinned revisions; only row indices, text hashes and verdicts are stored here):
Lakera/gandalf_ignore_instructions @04737b65 (test split, 112), JailbreakBench/JBB-Behaviors @886acc35 (harmful 100, benign 100),
Anthropic/hh-rlhf @09be8c5b (helpful-base test, seeded sample of 200, seed 20261120).

Results (claims_used_for_finale.json, type MEASURED 20 Nov 2026):

* Gandalf attacks blocked: regex 15 of 112, qwen3guard 61 of 112, both 63 of 112. JailbreakBench harmful: regex 0 of 100,
  qwen3guard 99 of 100.
* False positives: HH-RLHF helpful 3 of 200; JailbreakBench benign look-alikes 59 of 100 (a deliberately hard set: benign
  requests phrased like the harmful ones).
* Guard latency per call (slot reset + moderation, laptop CPU, 6 threads): p50 602 ms, p95 726 ms; 0 errors in 512 texts.
* Timing side channel with the guard on: unpadded, red's latency gives the decision away (held-out accuracy 1.000 against a
  majority baseline 0.800, p = 0.001). With deadline release at D = 4000 ms (calibrated by the P4 rule from the guard-mode
  decision times: p99 3818 ms + 100 ms reserve, rounded up) accuracy 0.395 against baseline 0.800, p = 0.846: no leak detected
  (inconclusive as to absence), 0 overruns, 0 cut-offs. Cost: +1516 ms median for answered requests. The tag's D = 1400 ms
  cannot hold the guard (fastest guard-mode decision 2048 ms: every answered request would be cut off). One execution, not
  three; the guard refuses some payloads in every configuration, so classes are 160 refused / 40 answered (see confounders).
* `scripts/real_model_demo.sh --guard`: 17/17 checks (the tag's 13 unchanged + 4 guard checks),
  transcript `finale_package/terminal/t7_real_model_demo_guard.txt`.

What the guard does not do: it misses 51 of 112 Gandalf prompts (mostly indirect password extraction), it blocks many benign
requests that look harmful, and it is one 0.6B classifier: an attacker who can query it offline can search for evasions.

## Part B: n8n incident relay

`aegis/notify.py`, installed from `aegis/__init__.py` only when `AEGIS_N8N_WEBHOOK` is set. After a run is SEALED (red already
stopped, so no timing channel), a daemon thread POSTs a redacted notice: run id, state, verdict counts, detectors fired,
severity, the sealed artifacts digest and the audit head at the seal; never payloads, outputs, canaries or the model's text
(`tests/test_finale_p16_notify.py` P16B02 checks the exact bytes). Signed `v1=HMAC-SHA256(secret, timestamp + "." + body)`,
2 s timeout; loopback only unless `AEGIS_N8N_ALLOW_REMOTE=1`; the secret file must be 0600 and owned by the operator. The
delivery result is appended as one audit entry `notify.delivery` after `run.sealed`.

n8n 2.48.6, `docker.io/n8nio/n8n@sha256:eafe4860…6619`, rootless Podman on an `--internal` network (no route out), published on
127.0.0.1 only (`tools/n8n/start_n8n.sh`). Workflow `tools/n8n/aegis_incident.json`: checks the HMAC (constant time) and a
5-minute timestamp window, answers 401 otherwise; routes on severity (high / medium / low) into an incident log.

| file | what |
|---|---|
| `notify_e2e/result.json` | `evaluation/notify_e2e.py`: two real-model runs with the guard (mode both). Live n8n: SEALED, `notify.delivery` ok, HTTP 200, the incident logged on route high. n8n down (closed port): SEALED, `notify.delivery` ok=false (URLError) audited, `verify_run` ok. |

Live HMAC test (P16B10, against the running n8n): a valid notice gets 200; a forged signature, a changed body, a timestamp older
than 5 minutes and an empty signature get 401.
