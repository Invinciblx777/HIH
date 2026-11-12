# AegisLab threat model and residual risk

Validation date 22 Oct 2026 · single host · numbers come from `evidence/validation_2026-10-22/` (commands in its `README.md`). Nothing here is a proof of security; every "0 found" is a finite test on one configuration.

Updated 10 Nov 2026 (Grand Finale P2): rows 4, 7, 8 and 9, section 2 and section 8. The container-free and container-only measurements were re-run on the changed code into `evidence/finale_rebaseline_2026-11-10/` with identical results; the real-model and timing figures below were recorded before that change (see section 8).

Updated 10 Nov 2026 (Grand Finale P3): rows 3, 4, 5 and 10, sections 5 and 7, and section 9. The real model now runs **live**. The real-model experiments were **re-measured** on the current code into `evidence/finale_p3_2026-11-10/`. The first real-model timing execution was recorded. Still **untested**: GPU, accelerator KV cache, other inference servers and builds (section 9).

## 1. Labels used

| Label | Meaning |
|---|---|
| **Verified** | Implemented, and an experiment in this repository exercises it (result cited). |
| **Partial** | Implemented for some cases; the gap is named. |
| **Assumption** | Not enforced by AegisLab; the guarantee holds only if it is true. |
| **Future** | Not built. |

## 2. Trust model (what must stay trusted)

| Item | Where | Must hold for the audit guarantee |
|---|---|---|
| Broker public key | pinned by the reviewer out of band (`broker_public_key.b64`, compare `signing_key_id`) | The verifier uses *this* key, never a key found next to the log. |
| Broker private key | `var/keys/broker_ed25519.pem`, mode 0600, unencrypted, same Unix user as the broker | Not readable by anyone who can edit the logs. **Same-user on this prototype** (see 5.7). Since finale P4 no container runs as that host UID: each runs as its own subordinate UID, which the 0600 file refuses (section 10.2). A compromise of the host user itself still reaches the key (rows 7 and 8). |
| Reviewer vault | `var/reviewer_vault/<run>.jsonl` (override: `AEGIS_VAULT`) | At least one of {vault, anchor store, the bundle the reviewer exported} survives unmodified. |
| Terminal anchor | `var/anchors/<run>.terminal.json`, mode 0444 (override: `AEGIS_ANCHORS`) | Same. Point `AEGIS_VAULT` / `AEGIS_ANCHORS` at storage the run-directory writer cannot reach (separate mount, append-only volume, another host). On one filesystem under one user they are **separate copies, not separate trust domains**. |
| Exported bundle | `aegis.evidence.export_bundle` → `audit.jsonl`, `reviewer_checkpoints.jsonl`, `terminal_anchor.json`, `broker_public_key.b64` | The reviewer copies it off the host at release time. |
| Verifier | `python -m aegis.verify_cli` | Runs in an environment the attacker does not control. |
| Host kernel, Podman/crun, broker process | the host | Uncompromised. |
| Reviewer identity | local demo token | A real deployment needs SSO with run-scoped claims. |

**Not defended:** an attacker who can simultaneously rewrite every independent copy (vault, anchor store, exported bundle), hold the signing key, or control the verifier can forge a consistent history. `scripts/security_demo.sh` step 7 demonstrates exactly this case.

### How the audit chain closes (new in this validation)

* Every checkpoint is signed over `{v, run_id, seq, head, event_count, cp_seq, prev_cp, ts, reason, key_id[, state]}`; `prev_cp` is the hash of the previous checkpoint, so checkpoints form their own chain (removal, reordering, splicing are detected).
* When a run reaches `RELEASED` or `FAILED`, the broker signs **one** terminal checkpoint (`reason: terminal`, `state`), writes it to the vault and to the anchor store, and closes the signed chain. Later events (for example denied reads of a released run) go to `post_terminal.jsonl`, unsigned and informational.
* The verifier **fails closed**: no terminal checkpoint or anchor → not valid. `--allow-in-progress` is the explicit opt-out and reports `terminal_verified: false`. The submitted `DEMO-001` bundle predates terminal checkpoints, so strict verification rejects it by design (see `evidence/validation_2026-10-22/README.md`).

## 3. Threat table

Measured results are quoted from the files named in the last column of section 4.

| # | Threat | Attacker capability | Protected asset / boundary | Existing mitigation | Experiment performed | Measured result | Residual risk | Next mitigation |
|---|---|---|---|---|---|---|---|---|
| 1 | Red attack-payload leakage | Blue participant, observer or unauthenticated caller; blue defence runner | Red payloads (sealed store); red→blue boundary | Payloads only in `sealed/`; broker is the only path; API roles; artifacts 403 until a reviewer releases; monitoring stream has no payload text; frozen-config and attack-pack digests hidden from non-privileged roles until release (a digest of a guessable file is a confirmation oracle) | Access matrix (6 identities × 4 lifecycle states × 9 operations, plus 9 public GET paths); marker scan for a synthetic payload, canary, tokens, PEM header; real-model run scan | 212 cases, 181 expected denials, 181 denied, **0 unauthorized successes**; 216 public response bodies scanned, **0 marker hits**; real-model runs: 270 responses × 66 markers, **0 hits**, 21/21 unauthorized artifact reads refused | The defence runner sees payloads by design (isolated, no network). Broker and reviewer see everything. After release participants see payloads. | Per-run signed claims; broker on separate infrastructure; confidential-computing enclave |
| 2 | Blue defence/config leakage | Red sandbox; red participant; observer | Defence configuration; blue→red boundary | Frozen config mounted read-only into the defence runner only; red mailbox ops (`read_artifact`, `get_verdicts`, `release_results`) denied; config digest hidden pre-release; red never gets a path to `frozen/` | 5 forbidden requests per run from inside the red container; in-container probes of 8 foreign paths, 3 network targets, write attempts; matrix | Submitted run: 150/150 denied, 90/90 connects failed, 90/90 paths absent (15 Oct). Re-run under the new code (22 Oct): 150/150 denied, 90/90 connects failed, 240/240 foreign paths absent (8 paths × 30 runs; 5 paths were added to the probe set) | Red legitimately sees refusals and can map the defence over many queries (black-box inference). | Query budgets; response randomisation evaluated per defence |
| 3 | Unauthorized model input/output access | Red/blue participant, observer; tenant containers | Prompts and completions | Model mailbox reachable only by the broker; outputs stored in `sealed/`; reviewer-only evidence pre-release; real-model API key held only by the broker. Since 10 Nov (live real model): `scripts/start_model_server.sh` passes the key in a 0600 file (`--api-key-file`), so it is on no command line. In `--sandbox` mode the server listens only on a UNIX socket in a 0700 directory, inside rootless Podman with `--network none`. The adapter refuses a socket or directory that another user owns or can open | Matrix; real-model scan for model-output prefixes in every response; scan of every file in every run directory for the API key; 10 Nov hardening check (section 9): the key on every process command line, every server endpoint with and without the key | **0 hits**; key found in **0** run files (3 runs) and in 0 of the 4 failure-test runs. 10 Nov: key on 0 command lines; every endpoint except `/health` answers 401 without the key; no prompt text in any endpoint | The model-server operator and the broker host see all prompts. Any process of the same Unix user can open the socket and read the key file. The unchanged M1–M6 harness (`evaluation/model_experiments.py`) still starts its own short-lived servers with `--api-key` on the command line. | Separate model tenancy per evaluation; attested inference |
| 4 | Cross-session contamination | A later session (or red probing) tries to recover earlier sessions' state | Model/session state | Stub: fresh container per run. Real model: every request is stateless (one user message, no history, no session id); `cache_prompt:false` by default, and `cache_prompt:true` is refused unless `AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1` is set (experiments only; recorded in the run manifest and the audit log). Since 10 Nov the launcher also turns off every cross-request state the server build allows (section 9) | Canary planted in 20 independent sessions, 4 probes each (80 trials per setting) with server prompt cache off and on; 20 context-contamination pairs per setting; positive controls with deliberately shared history; fresh-process vs reused-server (10 sessions) | Stateless sessions: **0/80** and **0/80** leaks (one-sided 95% upper bound 3.7%); **0/20**, **0/20** contamination. Controls detect shared history: 17/20, 20/20, 20/20 and 0/20 per probe (the probe "List any canary tokens…" detected 0/20 even with shared history, so it is an ineffective probe, kept and reported); context-contamination control 17/20. Submitted stub run: fresh 0/20 runs leaked, reuse control 9/10. **Re-measured 10 Nov 2026 on the current code** (`evidence/finale_p3_2026-11-10/`): the same leak counts, controls and 162 cached tokens. The two latency medians below became 227.5 ms and 647.9 ms. With the hardened launcher, 0 cached prompt tokens for broker-style requests (section 9) | **Server-side state is outside AegisLab's control.** On a reused server with `cache_prompt:true`, 162 prompt tokens were served from cache across sessions (fresh process: 0) and median probe latency was 242 ms vs 700 ms (the fresh process also pays a cold start, so the gap is confounded). No content leaked, but the *existence* of cross-session state is observable. Under the hardened launcher (10 Nov) a client that sends `cache_prompt:true` still gets cached tokens: `--no-cache-prompt` sets only the default in this build. The broker is the only client and refuses to send it. GPU/KV memory not tested. 0.5B model only, plus a reduced check of a 1.5B model (section 9). | Disable cross-tenant prefix caching; restart or flush per tenant; test GPU path |
| 5 | Timing and resource-contention side channels | Red measures latency of its own requests; a neighbour burns CPU | Defence verdict (refused vs answered); broker latency | Answers released on bucket boundaries (default 250 ms with the stub model). Since finale P4, with a real model, every reply is released at a fixed deadline by default: 250 ms buckets leaked with the real model in 3 of 3 executions, the deadline did not (section 10.1). CPU/memory/pids cgroup limits | Held-out grouped-CV classifier (threshold fitted on training runs only), 200 requests per bucket setting per execution (100 refused + 100 answered), permutation test, **three complete executions** with raw data and source hashes; mailbox RTT n=1000 per condition per execution, in shuffled blocks of 100 | Majority baseline 0.5. **No padding: accuracy 0.795–0.800** (p=0.001 in all three). **100 ms: 0.510–0.545; 250 ms: 0.495–0.555; 500 ms: 0.495–0.510**: no padded test is significant (smallest permutation p 0.136 among nine). This is **not proof of absence**: n=200 cannot tell an accuracy up to about 0.57 from chance. Cost at 250 ms: median of answered requests +198 to +201 ms; run wall time about 1.8–2.2 s → 3.9–4.4 s. RTT median idle 2.59–2.84 ms; neighbour limited to 1 CPU 2.53–2.88 ms (no measurable change); **unrestricted neighbour 3.63–4.16 ms (+37.5% to +51.7%), p99 6.75–8.18 ms**. Earlier executions (earlier code hash; one with no raw file) are historical and are not used here. **Real model, ONE execution (10 Nov 2026, `evidence/finale_p3_2026-11-10/timing_real_model/`)**: Qwen2.5-0.5B in the sandboxed server, 20 runs per setting, 200 requests per setting (140 answered, 60 refused). Unpadded, answered requests took 264–1956 ms. **At 250 ms the signal is fully readable: accuracy 1.000 (p=0.001, majority baseline 0.700)**. At the p99 bucket from calibration (**1600 ms**): accuracy 0.640, p=0.055, not significant (Bonferroni α 0.025), at +651 ms median per answered request. Some answered requests still crossed that bucket (padded p99 3326 ms vs 1733 ms max refused) | 10 distinct payloads, label confounded with payload. Stub latency is a constant sleep. A real model's variable latency crosses bucket boundaries: measured 10 Nov in one execution (see the result column). The 250 ms default does not hide it; a bucket sized from this host's p99 did, in that execution. The real-model result is one execution on one host, with the label confounded with the payload (3 of the 10 attacks are always refused). The code default stays 250 ms. A single-threshold adversary is weak. Cache and memory-bandwidth channels not measured. cpuset pinning not applied (controller not delegated to rootless users). RTT block medians vary by about 1 ms and "idle" means no CPU-hog neighbour, not a quiet host. | Bucket sized from the model's latency distribution (measured to work once at the p99, 1600 ms here; not yet the default); constant-time scheduling per tenant; dedicated cores / cpusets; stronger adversaries |
| 6 | Audit modification, deletion, truncation | Anyone who can edit `var/runs/<id>/` (hostile participant on the host, operator error) | Integrity and completeness of the evidence log | Hash chain; chained signed checkpoints; signed terminal checkpoint; anchor store; fail-closed verifier; reviewer bundle | 19 tamper categories × 30 real released runs, in-memory copies; 5 disk-level variants × 10 bundles through the CLI; all 10 requested adversarial cases as unit tests | Clean 30/30 accepted. Every category **30/30 detected**. Original gap (freeze checkpoint only): **0/30 before, 30/30 now** (fail closed), 30/30 with a retained anchor. CLI: 10/10 genuine accepted, 40/40 tampered rejected | A forger who holds the signing key **and** replaces every retained copy is not detected. A broker that signs false entries is not detected. | Key in KMS/HSM; publish the terminal head to a transparency log or a second party at release; separate-host vault |
| 7 | Signing-key compromise | Reads `broker_ed25519.pem` (same Unix user). Until finale P4 this included any tenant that escaped its container (`--userns keep-id`). Since P4 an escaped container process is a subordinate UID that cannot read the key (section 10.2); it must first gain the host user | Authenticity of checkpoints | File mode 0600; key id recorded in every manifest and checkpoint | Demonstrated: step 7 of the security demo forges a consistent history with the key and passes verification | **Not mitigated by design on this prototype** | Total loss of audit authenticity for runs signed with that key. Since P4 a reviewer countersignature held off the host detects a re-signed history (section 10.7, Partial) | Done in P4: tenants under separate UIDs (10.2), reviewer countersignature (10.7). Future: KMS/HSM for the key, key rotation with key-id pinning |
| 8 | Host-kernel or container-runtime compromise | Kernel/runc/crun escape from any tenant container | Everything | Rootless Podman, `--network none`, read-only rootfs, all capabilities dropped, `no-new-privileges`, default seccomp, private SELinux labels, pids/memory/CPU limits; in-container observation: CapEff=0, NoNewPrivs=1, Seccomp=2 | In-container self-checks only (no escape attempts) | Self-checks as listed; no exploit testing was done | **Containers share the host kernel.** One kernel bug defeats the boundary. Since P4 the escaped process is a subordinate UID, not the key owner (10.2), so key theft needs a second step to the host user; a kernel exploit can take that step | gVisor / Kata / Firecracker microVMs (gVisor not done in P4: runsc is not installed on the test host); per-tenant hosts |
| 9 | Monitoring-based leakage, including the monitor as a covert or feedback channel during a run | Observer, red or blue participant, any unauthenticated caller reading the monitor stream (API `GET /api/runs/{id}/events`, console timeline and run view) | Payload/output/config content; red-chosen strings; per-attack refusal reasons; metadata | The stream never holds a tenant-chosen string: attack ids, op names and claimed tenants appear only as digests (the attack event carries the broker's own counter). **Per-role views (since 10 Nov):** operator and reviewer see every event live, alerts included. Anyone else, while the run is CREATED, FROZEN or RUNNING, sees run-level events only, with control-plane text and no sequence numbers, digests, per-request denials or per-attack alerts (`canary.leak`, `model.secret_withheld`, `model.error`). Those alerts would tell red why an attack got the uniform refusal. From SEALED on everyone sees the stored stream. Error responses carry fixed messages | Substring scan of every monitor stream and API body for payload/output/canary/key/token markers. Since 10 Nov: a hostile attack id carrying a marker, scanned in every unauthenticated and participant response before SEALED (unit tests with the real broker, and one live Podman run) | **0 occurrences**: 894 events / 75 strings (15 Oct), 120 events / 66 markers under a real model, 216 public bodies in the matrix (re-measured 10 Nov: 0 in 216). Hostile attack id, live run: **0 hits in 1,320 responses before SEALED** (1,200 while RUNNING); the code before the change gave 258 hits | Counts and timing stay visible: the run's `attack_count` and `evaluated` counters and the time of each attack event. A red tenant could signal a few bits through them. Run ids, the run state and the operator's tags are public by design | Quantised event timing; per-run identities so participants see only their own runs |
| 10 | Model-server failure; unsupported inference-state isolation | Server down, slow, wrong credentials, malformed replies | Run integrity; confidentiality of credentials | No automatic fallback to the stub; endpoint unreachable at start → run `FAILED`; per-request errors become a uniform refusal for red; three consecutive errors abort; fixed secret-free error strings; loopback-only unless `AEGIS_MODEL_ALLOW_REMOTE=1`; no proxy, no redirects | Live: healthy baseline, 50 ms timeout, wrong API key, server stopped. Unit tests with a fake server: 500, 401, slow, bad JSON, huge reply, redirect. 10 Nov: the same four live cases re-run on the current code (M6), E5 re-run, and the live real-model console and demo (section 9) | Timeout run: 3 `model.error(timeout)` then `FAILED`; wrong key and dead server: `FAILED` before any attack; **all four `FAILED` runs end with a verifying `FAILED` terminal checkpoint and no key in any file**. 10 Nov: identical (M6), E5 9 of 9 checks hold | Cannot reset server memory; GPU, CUDA contexts and hardware channels are untested; only llama.cpp b11819 on CPU was exercised. Since 10 Nov the server can run sandboxed (rootless Podman, `--network none`, read-only, all capabilities dropped). That limits what a compromised server process can reach. It does not isolate tenants inside one server. | Per-tenant server instances; verified cache flush hook; GPU-isolation experiments |
| 11 | Credential and token exposure | Anyone reading URLs, logs, evidence, or timing of token checks | API tokens; model API key | Tokens only in the `X-Aegis-Token` header (the `?token=` download path was removed); constant-time comparison; model key never written to manifests, audit, monitor or reports; `AEGIS_MODEL_API_KEY_FILE` must be mode 0600 | Unit tests; log/stdout capture during API calls; file scans | Tokens and key absent from captured logs and run files | `AEGIS_DEMO_MODE=1` returns every token to any local caller of `GET /api/demo/identities`. **Demo only; never enable outside a local demo.** | SSO/OIDC with run-scoped claims |
| 12 | Tenant-side denial of service through the mailbox | Red container creates FIFOs, links, directories, huge or deeply nested JSON in its spool | Broker availability | `O_NOFOLLOW` and `O_NONBLOCK`, regular-file and 64 KiB checks, JSON depth guard; every rejected entry is deleted | FIFO, directory, symlink, 100 000-deep JSON, array-root JSON, malformed commit/attack messages | **A real bug was found and fixed:** a FIFO planted in the red spool blocked the broker indefinitely, and rejected entries were re-processed forever. All cases now rejected in < 2 s | A tenant can still flood valid messages until the 300 s run deadline. | Per-run quotas and rate limits |

## 4. Where each number lives

| Area | File |
|---|---|
| Audit tamper/truncation, CLI-level checks, original-gap comparison | `evidence/validation_2026-10-22/audit_tamper.json` |
| Access matrix | `evidence/validation_2026-10-22/isolation_matrix.json` |
| Real-model experiments (M1–M6) | `evidence/validation_2026-10-22/model_experiments.json` |
| Timing and RTT (current: three executions, raw data) | `evidence/closeout_2026-10-22/timing/` |
| Timing and RTT (earlier executions, historical) | `evidence/validation_2026-10-22/timing.json`, `timing_execution_2.json`; `evidence/closeout_2026-10-22/timing/historical/` |
| Original E1–E9 harness re-run under the new code | `evidence/validation_2026-10-22/e1_e9_rerun/` |
| Submitted (15 Oct) numbers, untouched | `evidence/results.json`, `evidence/RESULTS.md`, `evidence/DEMO-001/` |
| Finale P2 re-baseline (10 Nov): access matrix, audit tamper suite, Phase 2 role matrix, E1–E9 re-run on the changed code; acknowledged source drift for the saved real-model runs | `evidence/finale_rebaseline_2026-11-10/` (`REMEASURED.json`, `SOURCE_DRIFT.json`) |
| Finale P3 (10 Nov): real-model E1–E5 and M1–M6 re-measured on the current code, the hardened model server, one real-model timing execution, the live console's bundle, a reduced 1.5B check | `evidence/finale_p3_2026-11-10/` (`README.md`, `SOURCE_DRIFT.json`) |

## 5. Assumptions and limits that a judge may probe

1. **Single host, shared kernel.** Containers are not a strong boundary against a kernel exploit.
2. **Local demo identities.** Tokens in `var/keys/tokens.json`; the reviewer is a trusted human holding a token.
3. **Filesystem state.** JSON/JSONL files; the audit store, vault and anchor store are different directories under one Unix user unless relocated with `AEGIS_VAULT` / `AEGIS_ANCHORS`.
4. **The broker is trusted.** It sees every payload and signs every checkpoint; a lie told before signing is not detectable.
5. **Finite tests.** Zero findings in n trials gives an upper bound (rule of three), not a proof. Sample sizes are in the result files.
6. **Real-model evidence is narrow:** one 0.5B model (plus a reduced E1/E3 check of a 1.5B model, 10 Nov), llama.cpp b11819, CPU, application-visible leakage only.
7. **Key custody:** see row 7.
8. **Timing:** the mitigation costs latency (row 5), reduces but did not eliminate a measurable signal at 100 ms, and was only judged indistinguishable from chance at 250/500 ms with n=200 **on the stub model**. With the real model (one execution, 10 Nov), 250 ms leaves the signal fully readable (accuracy 1.000). Only a bucket at the measured p99 (1600 ms) gave a non-significant result.

## 6. Phase 2 adversarial addendum (23 Oct 2026)

Attacks were executed against the local prototype in disposable state directories and, for the sandbox boundary, inside real rootless Podman containers (`tests/test_phase2_*.py`, `evaluation/phase2_matrix.py`; results and before/after logs in `evidence/phase2_2026-10-23/`). Findings, fixes and counts are in `PHASE2_SECURITY_REPORT.md`. This table says, per attacker, what the design is meant to stop and what it trusts away.

| # | Attacker | Meant to be stopped | What was executed | Trusted away (not defended) |
|---|---|---|---|---|
| 1 | Malicious red tenant (code in the red sandbox) | Reading blue config or other tenants' data; writing outside its mailbox; forging identity; blocking the broker | Links, hard links, FIFOs, sockets, directories planted at predictable names; mailbox directory replaced; hostile and oversized messages; floods; identity fields in messages | Learning allow/refuse outcomes through authorised outputs (documented timing and refusal channel) |
| 2 | Malicious blue tenant (config author) | Seeing red payloads before release; stalling or crashing the defence runner | Catastrophic regular expression; invalid configs; changing the config around the freeze | Choosing a config that blocks everything (it is scored as such) |
| 3 | Model worker | Reading any file other than its own mailbox; reaching the network; altering the run | Probe from inside the model-role container; odd or oversized replies | A model that simply answers badly |
| 4 | Observer (no or unknown token) | Anything beyond the redacted monitoring stream | Role x operation x state matrix incl. RUNNING and FAILED; unknown run ids; marker scan of every public body | Learning that a run exists and its lifecycle state (public by design) |
| 5 | Authenticated but wrongly privileged user | Operations outside the role | Same matrix; token mix-ups; tokens in URL, cookie, other headers; components called without the API | Tokens are global per role, not run-scoped (local demo identities) |
| 6 | Process writing in its permitted area | Redirecting or blocking the broker | See 1 | A tenant destroying its own mailbox ends only its own run (sealed incomplete) |
| 7 | Resource exhaustion / interference | Unbounded growth of the signed log; stalls | Denial floods (anonymous and tenant), process and memory limits in the sandbox, CPU-contention comparison | Cache and memory-bandwidth channels; a neighbour on the same host |
| 8 | Log editor without the signing key | Undetected modification, deletion, reorder, truncation | 16 mutation classes, foreign-run material, key substitution, via the CLI on copies | None beyond the key and retained-copy assumptions |
| 9 | Compromised trusted broker | Not stopped | A false but consistent run was produced and verified (accepted limitation, shown on a fixture) | Everything the broker writes or signs |
| 10 | Signing-key theft plus control of every retained copy | Only if the reviewer wrote down the terminal hash | A full re-signed history verifies; `--expect-terminal-hash` rejects it | A reviewer who kept nothing out of band |

The reviewer-side countermeasures added in Phase 2 are optional pins: `verify_cli --pubkey` (also with `--bundle`) and `--expect-terminal-hash`. They do not make the broker trustworthy; they remove the reviewer's dependence on files the attacker can rewrite.


## 7. Phase 3 addendum: LLM-native isolation (23 Oct 2026)

Full analysis, denominators and provenance: `PHASE3_LLM_SECURITY_REPORT.md`; raw data: `evidence/phase3_2026-10-23/`. Real-model results come from one 0.5B model on one CPU llama.cpp build and are application-visible behaviour only. GPU memory, accelerator KV cache and hardware side channels were **not tested**.

| Boundary | Enforced by | Depends on | Outside our control |
|---|---|---|---|
| Conversation context between runs | The adapter: one user message per request, no history, no session or run identifier, `cache_prompt: false` (tests P3B04, P3B05; wire records in E2/E4) | nothing | A gateway placed in front of the adapter |
| Inference-server state (prefix / KV cache) | The per-request `cache_prompt: false` field | The server honouring it; E3 shows 0 cached tokens in 120 trials with it, and a working cache oracle (AUC 1.00) when it is `true` | Server start-up flags (`--cache-ram`, idle-slot caching), other clients holding the API key |
| Model output reaching a tenant | The broker: another run's canary (token, digits, separated digits, 8-digit fragments; runs still in progress included) and the model API key or an API token are withheld (uniform refusal) and recorded; the sealed copy has secrets redacted | The detector's coverage: a re-encoded canary (base64, cipher, spelled-out digits) is not recognised (test P3B02d) | The model's own behaviour |
| Failure of the model service | The adapter (one time budget for the whole exchange, JSON content type, size cap, fixed errors) and the broker (no stub fallback, three consecutive errors fail the run, any error marks the run incomplete) | | |
| GPU / accelerator memory | nothing | | Entirely untested |

10 Nov 2026 (finale P3), the same boundaries re-measured on the current code: E1–E5 in `evidence/finale_p3_2026-11-10/llm/` (identical isolation results; differences in two control and latency figures are listed in section 9). The server-state row now also has the hardened launcher. `--no-cache-prompt --cache-ram 0 --no-cache-idle-slots` and the other flags close what the build lets them close. A client sending `cache_prompt: true` is still served from cache, so that row still **depends on** the broker being the only client.

Also fixed in Phase 3: first creation of the signing key is atomic and private from the first byte (`aegis/crypto.py`, test P3K01).

Residual items found in Phase 3: ~~the adapter accepts `AEGIS_MODEL_EXTRA_JSON='{"cache_prompt": true}'` without a guard~~ (closed 10 Nov, section 8); `llama-server --api-key` on a command line is visible to local users (use `--api-key-file`; done in the harness and the launcher on 10 Nov, section 9); `/slots` and `/props` answer to anyone holding the key (no prompt text was found in them in this build; under the launcher `/slots` is off, `GET /props` cannot be turned off).

## 8. Grand Finale P2 update (10 Nov 2026)

What changed in the code (commit `c018c52`; tests `tests/test_finale_p2_*.py`):

| Item | Change | Evidence |
|---|---|---|
| Monitoring side channel (row 9) | Before: the stream needed no identity, worked while a run was RUNNING, and carried the raw red-chosen attack id (up to 64 characters). Its per-attack alerts revealed refusal reasons. Now: digests instead of tenant strings, plus per-role views (row 9) | `test_finale_p2_monitor.py`. Live run: 0 hits before SEALED (258 on the earlier code) |
| `cache_prompt` guard (row 4) | `cache_prompt:true` is refused unless `AEGIS_UNSAFE_EXPERIMENT_SHARED_PROMPT_CACHE=1`. A missing or null value is sent as an explicit `false`. The opt-in is recorded in the frozen manifest (`unsafe_shared_prompt_cache_experiment`) and in the audit entry `model.session_opened`. The live monitor shows a warning. The experiment harness opts in for its cache-on controls only | `test_finale_p2_model_cache_guard.py` |
| Tenant-storage race | The first `create_run` on an empty state directory copied the sample tenant files in place, so a concurrent creator could read a half-written file. Now: private name, then an atomic rename | `test_finale_p2_tenant_storage.py` (fails on the earlier code); `test_P2L03` passed 200 consecutive times |
| Release after signing | If strict verification failed after the RELEASED terminal checkpoint was signed, the record turned FAILED while the signed state said RELEASED. The record now stays consistent with its signature. The release is marked unverified, and artifacts, the evidence report and outcomes stay withheld. An unsigned post-terminal entry says why | `test_finale_p2_release_consistency.py` |
| Key custody stated (rows 7, 8, section 2) | No code change. With `--userns keep-id`, a container escape is key theft and forgeable evidence. Fix planned for finale P4 | — |

**Re-baseline.** `evidence/finale_rebaseline_2026-11-10/` holds the measurements that need no real model, re-run on the changed code.
- Every security figure is identical: 181/181 denied, 0 marker hits in 216 bodies, 92/92 traversal cases, 19 tamper categories each 30/30, CLI 10/10 and 40/40, the Phase 2 matrix's 560 attempts with 419/419 denials, and E2 150/150, 90/90, 240/240.
- The real-model results (rows 3 and 4, section 7) and the timing results (row 5) were **recorded before this change** and were not re-run.
  - `SOURCE_DRIFT.json` states, per changed file and per experiment, why the change does not affect what was measured.
  - `evaluation/check_claims.py` accepts exactly those changes and fails on any other.
  - The timing path is affected only by a shorter monitor string written after the padded sleep.

**Public read-only demo.** https://aegislab-demo.onrender.com (Render) serves the console read-only (`AEGIS_PUBLIC_DEMO=1`). An older copy at `aegislab.vercel.app` still serves outdated code (28 Oct 2026, where Verify fails with HTTP 403): do not use it.
- There is no operator session and no launch code, and it runs no containers and no model.
- Every write is refused except bundle verification and tampering with a disposable copy, both rate-limited.
- The live console (`scripts/start_prototype.sh`) stays loopback-only.
- The public demo does not change any row above: it holds no tenant data and runs no evaluation.

## 9. Grand Finale P3 update (10 Nov 2026): the real model, live

Code: commit `09b53d1` plus the P3 scripts (`tests/test_finale_p3_*.py`). Evidence: `evidence/finale_p3_2026-11-10/` (its `README.md` lists every command). One host: 16 CPUs, no GPU, Fedora, SELinux enforcing, rootless Podman 6.1.3.

**What is live now.**
- `scripts/real_model_demo.sh` checks four things with Qwen2.5-0.5B answering in real time:
  - stateless sessions;
  - a positive control that must leak;
  - the broker withholding that leak, with its audit entry;
  - strict verification and tamper rejection of the bundle.
- `scripts/start_real_model_console.sh` runs the console with every lab run answered by the real model, labelled "REAL MODEL · LIVE" with the model file, its sha256 prefix, "llama.cpp CPU" and "loopback".
- Neither falls back to the stub. An unreachable server makes the run `FAILED`; errors reach red as the uniform refusal.

**The model server.** `scripts/start_model_server.sh` checks the model and binary sha256 and writes the key to a 0600 file (`--api-key-file`). It starts llama-server b11819 with every cross-request state the build allows turned off: `--no-cache-prompt --cache-ram 0 --no-cache-idle-slots --no-kv-unified --ctx-checkpoints 0 --cache-reuse 0 --no-context-shift --no-slots`, and no `--slot-save-path`, `--metrics` or `--props`.

With `--sandbox` the server runs in rootless Podman:
- `--network none`, read-only root filesystem, all capabilities dropped, `no-new-privileges`;
- 64 pids, 3 GiB memory, 6 CPUs;
- binary, model and key mounted read-only;
- a UNIX socket in a 0700 directory as the only way in.

The adapter checks the socket's owner and the directory's mode before every connection.

| Measured (`model_server_hardening/`, 30+30 trials per cell, both modes) | Result |
|---|---|
| Cached prompt tokens, AegisLab requests (`cache_prompt:false`) | 0 of 60 per mode |
| Cached prompt tokens, field absent (server default) | 0 of 60 per mode; control without the launcher flags: 60 of 60, AUC 1.0 |
| Cached prompt tokens, client sends `cache_prompt:true` | **60 of 60, AUC 1.0, both modes: not closed by any flag** |
| `/slots`, `/metrics`, `POST /props`, slot save/restore | HTTP 501 (disabled) |
| Endpoints without the key | 401 everywhere except `/health` |
| Prompt text or planted marker in any endpoint | none |
| Key on any process command line | none |
| Inside the sandbox | only `lo`; `connect` to 1.1.1.1 fails (errno 101); root filesystem read-only; `CapEff` 0; `NoNewPrivs` 1 |

**Not closed by the launcher:**
- **Client-requested caching.** A client that asks for `cache_prompt:true` (the broker refuses to; P2 guard). Any process of the same Unix user can open the socket.
- **`GET /props`.** It needs the key and shows defaults and the model path, no prompt text.
- **Shared hardware state.** The KV cells of the single slot between requests, CPU caches, memory bandwidth and timing.

**Re-measured (10 Nov, same settings as 23 Oct).**
- **Same as 23 Oct.** E1 isolation trials: 0 of 1040 (0 of 104 sessions); controls 16 of 16 and 13 of 16; E2 0 of 26 runs; E3, E4 and E5. M1–M6 are identical except the M3 latency medians (below).
- **Differs from 23 Oct, both dates kept and printed by `check_claims.py`:**
  - E2 context-sharing control: 3 of 4 runs, 14 withheld (23 Oct: 2 of 4, 15).
  - E3 cache-off latency AUC: 0.41/0.47 (0.52/0.42).
  - M3 latency medians: 227.5 ms vs 647.9 ms (242.3 vs 700.1).

  These are controls and latency figures, not isolation results. The 23 Oct runs stay in `evidence/phase3_2026-10-23/` and are still checked.

**Timing with the real model (ONE execution).** At 250 ms padding the defence's decision stays fully readable: accuracy 1.000, p=0.001. At the p99 bucket (1600 ms) accuracy was 0.640, p=0.055, at +651 ms per answered request (row 5). The shipped default is still 250 ms.

**Still untested.**
- GPU and accelerator memory, the accelerator KV cache, CUDA contexts.
- Inference servers other than llama.cpp b11819 on CPU, and multi-slot (`-np` > 1) configurations under the launcher.
- Models other than Qwen2.5-0.5B (full) and Qwen2.5-1.5B (reduced E1/E3).

## 10. Grand Finale P4 update (11 Nov 2026): hardening

Code: branch `finale/p4-hardening` (one commit per task). Evidence: `evidence/finale_p4_2026-11-11/`, measured on commit e048ad9. The pinned files these tasks changed are acknowledged in `evidence/finale_p4_2026-11-11/SOURCE_DRIFT.json`; every claim a change affects was re-measured there (`evaluation/check_claims.py`, Part F).

### 10.1 Timing: decision-independent release, now the real-model default (task 1)

P3 measured once that 250 ms buckets do not hide the decision with a real model (accuracy 1.000). P4 adds a second release mode and measures both across three executions.

**Deadline release** (`runs.create_run(timing_deadline_ms=D)`). Every attack reply leaves at exactly t0 + D, refused or answered. The model is cut off 100 ms before D (`DEADLINE_RESERVE_MS`), and red then gets the uniform refusal; the outcome is `cut_off`, audited as `timing.cutoff`. Every decision-dependent write (sealed artifact, `attack.evaluated`, `canary.leak`, checkpoints, anomaly alerts) happens before the release, none after. An optional shadow call sends a length-matched neutral decoy to the model on input refusals (never the refused text). Tests: `tests/test_finale_p4_release_timing.py` (16).

**Measurement** (`evaluation/timing_deadline.py`, `evidence/finale_p4_2026-11-11/timing_deadline/`). The two P3 confounders are removed:
- balanced classes, 100 refused and 100 answered per setting and execution;
- every payload in both classes, by alternating two defence configurations.

D is fixed from a calibration phase before any classification run: p99 of the broker's decision time plus 100 ms, rounded up to 100 ms. Qwen2.5-0.5B, llama.cpp b11819 on CPU, sandboxed. The verdict rule was declared before the runs: a leak if p < 0.05/9 in any execution.

| Setting (real model) | Accuracy, 3 executions | Majority baseline | Permutation p | Added latency per answered request | Cut-offs | Verdict |
|---|---|---|---|---|---|---|
| none (control) | 1.000, 1.000, 1.000 | 0.500 | 0.001 each | 0 | 0 | leak (control) |
| 250 ms buckets | 0.945, 0.960, 0.950 | 0.500 | 0.001 each | +217 to +228 ms | 0 | **leak detected** |
| deadline D = 1300 / 1400 / 1300 ms | 0.495, 0.545, 0.575 | 0.515, 0.540, 0.515 | 0.560, 0.197, 0.044 | +519 to +621 ms | 3, 8, 3 % | no leak detected |
| deadline + shadow | 0.455, 0.505, 0.560 | 0.520, 0.535, 0.515 | 0.830, 0.472, 0.118 | +519 to +620 ms | 4, 7, 3 % | no leak detected |

Costs of deadline release:
- each 10-attack run takes 9.4 to 10.4 s longer;
- every reply leaves at most 1.35 ms after t0 + D, and no reply overran;
- the shadow call raises the model server's CPU time per run from 20.5–21.9 s to 24.9–27.2 s with no measurable gain.

The stub model, re-run on the P4 code (3 executions, n = 200 each; `timing_stub/`), gave the same picture as before. Unpadded accuracy was 0.640 to 0.800 (control). With padding it was 0.410 to 0.555 at 100, 250 and 500 ms, and no padded setting reached significance.

| Property | Label |
|---|---|
| 250 ms buckets do not hide the decision with a real model (3 of 3 executions) | Verified (measured) |
| Deadline release: no leak detected by this classifier in 3 executions | Verified (measured); not a proof of absence: n = 200 per execution cannot separate an accuracy up to about 0.57 from chance, and the third execution's p = 0.044 is below 0.05 though above the pre-declared threshold |
| Deadline release is the default for a real-model backend (`runs.default_timing`, D = 1400 ms or `AEGIS_TIMING_DEADLINE_MS`; shadow off). The stub keeps 250 ms buckets. An explicit choice is always honoured. | Verified (`tests/test_finale_p4_timing_default.py`) |
| D is right for another host, model or prompt length | **Assumption**: D was calibrated on the test host for Qwen2.5-0.5B with max_tokens 96. Elsewhere, re-run the calibration phase. A D that is too short raises the cut-off rate (answers lost); a D that is too long only costs latency. |
| Cut-offs reveal nothing | Partial: a cut-off is released at the same t0 + D as every other reply, and red sees the uniform refusal. But llama.cpp stops generating about 0.6 s after the disconnect, so the model server keeps working a little longer for cut-offs. This is not visible to red's latency; it was not measured as a separate channel. |
| Cache, memory-bandwidth and CPU-contention channels between tenants | Future (not measured) |

### 10.2 Containers no longer run as the key owner (task 2, F4)

Before P4 every container ran with `--userns keep-id`: as the broker's own host UID, which owns the unencrypted `var/keys/broker_ed25519.pem` and the model API key file. A container escape was therefore key theft and forgeable evidence (rows 7 and 8).

Now every container, the three tenants and the sandboxed model server, runs with `--userns auto:size=1024 --user 900:900` (`aegis/runtime.py`, `scripts/start_model_server.sh`). Podman gives each container its own range of the user's subordinate UIDs (`/etc/subuid`), so container UID 900 is a host UID that is neither the broker's nor any concurrently running container's. The key files stay 0600 and broker-owned. The broker keeps owning every shared directory (mailboxes, the model socket directory) and grants the one mapped host UID access with a POSIX ACL entry on exactly the mount sources, between `podman create` and `podman start` (`aegis/userns.py`). Nothing becomes group- or world-accessible.

Proof, from the live system (`evaluation/p4_userns_proof.py`, 13 of 13 checks, run twice: `evidence/finale_p4_2026-11-11/userns_proof/` on e048ad9 and `userns_proof_final/` on the final code 032eb84, with the same host UIDs). The broker is host UID 1000; the subordinate range is 524288 to 589823.

| Container (running at the same time) | Inside | Host UID (`podman top` huser, `/proc/<pid>/status`) | `uid_map` |
|---|---|---|---|
| model server (sandboxed llama.cpp) | 900 | 525188 (equals the socket owner and `launch.json` `server_process_host_uid`) | 0 524288 1024 |
| lab run P4U-RUN, model | 900 | 526212 | 0 525312 1024 |
| lab run P4U-RUN, blue | 900 | 527236 | 0 526336 1024 |
| lab run P4U-RUN, red | 900 | 528260 | 0 527360 1024 |

| Property | How | Label |
|---|---|---|
| No container process runs as the broker's host UID; all run as container UID 900 | Proof checks `lab_every_container_process_runs_as_container_uid_900`, `lab_no_container_host_uid_equals_the_broker_uid`, `lab_container_host_uids_in_the_subordinate_range`, `model_server_runs_as_container_uid_900_not_the_broker`; `tests/test_finale_p4_userns.py` | Verified |
| Concurrent containers have distinct host UIDs | Proof checks `lab_container_host_uids_distinct`, `model_server_host_uid_differs_from_the_concurrent_lab_containers`, and the table above. Podman reuses a range after its container exits, so distinctness holds among containers that run at the same time, not across time | Verified |
| A container that reads the key file is refused by the kernel | Proof negative control: raw `podman run` with the same flags and the scratch key directory bind-mounted read-only; reading the key gives errno 13 (Permission denied) | Verified |
| The key directory is never offered as a mount | `runtime._check_mounts` refuses it before podman runs (proof negative control a) | Verified |
| Key and token files broker-owned 0600; model API key file broker-owned 0600 | Proof checks `key_files_broker_owned_and_private`, `model_api_key_file_is_broker_owned_0600` | Verified |
| A kernel or runtime escape that gains the host user (UID 1000) | Out of scope of this change: the key is still an unencrypted file of that user | Not mitigated (row 7; KMS/HSM is Future) |

### 10.3 Re-encoded canaries (task 3)

`aegis/canary_scan.py` runs on every model answer, after the plain detector (`runs.canary_hits`, unchanged). It looks for every other run's canary in the following forms. Each is checked for the token, its lower and upper case, and its 12 digits.

- base64: standard and URL-safe, padded or not, at any byte offset, with line breaks inside;
- hex of the ASCII bytes;
- rot13;
- reversed;
- digits split by whitespace or punctuation;
- digits spelled out as words (zero to nine, alpha to foxtrot).

| Property | How it is enforced | Label |
|---|---|---|
| Caught encodings | `tests/test_finale_p4_canary_scan.py` P4C01 (11 cases), P4C20 (the broker withholds base64, rot13 and spelled forms, audit `canary.leak` with `reencoded`), `tests/test_phase3_llm.py` P3B02e | Verified |
| No false positives on ordinary output | P4C03: a 12-text benign corpus (prose, code, real base64 and hex blobs, number lists, NATO words) against 301 canaries, 0 hits | Verified (on that corpus) |
| Bounded | It never decodes the text: it encodes the canaries and slides fixed-length windows over normalised views. The text cap is 16,384 characters. The time budget is 50 ms. There is no recursion. A text over the cap or over the budget is withheld and audited as `canary.scan_incomplete` (P4C05, P4C06, P4C21). | Verified |
| Live, real model | `scripts/real_model_demo.sh` check 9: through the context-sharing control, run B's raw output carries run A's canary in base64 only. The plain detector does not see it; the broker withholds it and nothing reaches red in any encoding. | Verified (Qwen2.5-0.5B) |
| The model encodes on request | Measured: neither Qwen2.5-0.5B nor 1.5B produced a valid base64 of a canary when asked (0 of 5 each); both copy a base64 form they were given (5 of 5). In the demo the "encode" answer is the planted form, copied. | Measured, not a guarantee |

**Not covered (stated limits, test P3B02d):**
- Encodings applied twice or combined (base64 of the reversed token).
- Other bases (base32, base85, decimal bytes).
- Arbitrary ciphers and keyed encodings.
- Homoglyphs.
- Translation.
- Paraphrase with filler words between the digits ("it starts with seven, and then...").
- A token split across several replies.

`canary_scan.near_misses()` reports shorter fragments for the anomaly detectors: 6 to 11 digits, or a 12-character run of the base64 form. It never withholds. Server-side isolation remains the primary control. The detector is a second line.

### 10.4 Anomaly detectors (task 4)

`aegis/anomaly.py` runs six detectors on what the broker already sees. Each alert is an `anomaly.alert` audit entry: hash-chained and covered by the signed checkpoints. The seal adds one `anomaly.summary` entry with every detector, its threshold and its count.

| Detector | Threshold | Rationale (short) |
|---|---|---|
| `denial_burst` | ≥ 5 denied red requests within 10 s | Probing the policy. An honest client is never denied. |
| `forbidden_sweep` | ≥ 3 distinct forbidden operations in one run | A search for a policy gap. A client bug repeats one operation. |
| `mailbox_violations` | ≥ 2 red mailbox violations within 60 s | The tenant is tampering with its own mailbox to probe the broker's file handling. |
| `canary_near_miss` | fragments of one foreign canary in ≥ 3 attacks (6–11 digits), or in 1 attack (12 base64 characters) | Gradual extraction below the withholding rule. Six digits match by chance; three hits on one canary do not. |
| `model_cutoffs` | ≥ 3 cut-offs or model errors among the last 10 attacks | Prompts made to slow the model, or a failing backend. Either changes what the padding hides. |
| `latency_drift` | median broker overhead of the last 10 attacks > max(2×, +50 ms) the median of the first 10 | The padding margin is being eroded before slips or overruns show. |

The scripted red agent's forbidden probes fire `denial_burst` and `forbidden_sweep` in every probe run, which is the intended demonstration.

| Property | How | Label |
|---|---|---|
| Thresholds as stated | `tests/test_finale_p4_anomaly.py` P4A02–P4A08 test each threshold both at the value and just below it | Verified |
| Live only to operator and reviewer | `anomaly.*` events are not in `runs.PARTICIPANT_EVENTS`, so the participant view excludes them until SEALED (P4A11). The console endpoint `/api/lab/runs/{id}/anomalies` refuses participants (P4A30). | Verified |
| No content channel | Detectors never change, refuse or delay a reply. Red gets the same bytes whether or not a detector fired (P4A12). Foreign canaries appear only as digests (P4A05, P4A16). | Verified |
| No timing channel | Observation is in memory only, on every request. Alerts are written only inside a padded attack window or at the seal, never on a denial's reply path (P4A10, P4A14). With padding off, alerts wait for the seal (P4A15). In deadline mode every attack reply leaves at t0+D with or without alerts (P4A13). | Verified (deadline mode); bucket mode can slip one bucket if a write crosses the planned boundary, and the slip is counted |
| Operator view | Console, Audit, Signed audit log: the "Anomaly detectors" panel lists thresholds, rationale and the alerts with sequence, hash and signature coverage | Verified (P4A30, P4A31; console Playwright check) |

**Limits.**
- The thresholds are fixed and not tuned on adversarial traffic.
- An attacker who stays under every threshold is not flagged.
- Alerts raised by denials appear in the operator's live view only at the next padded attack or at the seal.

### 10.5 Small pins (task 5)

| Change | Where | Test | Label |
|---|---|---|---|
| The sandbox base image is pinned by digest, `python@sha256:e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c`, instead of a tag | `Containerfile`, `runtime.BASE_IMAGE`, `scripts/quickstart.sh`, `scripts/start_prototype.sh` | `tests/test_finale_p4_pins.py` P4P01, P4P02 | Verified |
| `pyproject.toml` states what the code needs: Python 3.12 or later, runtime dependencies fastapi, uvicorn, cryptography and httpx (the console imports FastAPI's TestClient), pytest only in the `dev` group | `pyproject.toml`; `uv.lock` regenerated by uv 0.13.7, every package version unchanged | P4P03; a Vercel-like `uv sync --frozen --no-dev` on Python 3.12 served the public demo (verify ok, session start 403, run creation 403) | Verified |
| The model launcher removes its run directory, which holds the API key, when it refuses to start (for example on a libgomp mismatch) | `scripts/start_model_server.sh` `die()` | P4P04 | Verified |

### 10.6 Capability tokens (SHOULD 6)

`aegis/captoken.py` and `POST /api/runs/{id}/capabilities` add signed, expiring tokens scoped to one run, one role and a subset of that role's operations. They are signed with a separate key, `var/keys/capability_ed25519.pem`, never with the evidence key.

| Property | Test | Label |
|---|---|---|
| Valid only on its run, only for its listed operations; refused on endpoints that are not run-scoped | `tests/test_finale_p4_captoken.py` P4K01 | Verified |
| Never wider than the role it names | P4K02 | Verified |
| The operator cannot mint the right to release; only the reviewer issues reviewer tokens; issuing needs a global role token (no delegation chains) | P4K03 | Verified |
| Expired, tampered, or signed with the evidence key: refused | P4K04 | Verified |
| Key separate from the evidence key, 0600, never mountable into a container | P4K05 | Verified |
| Issuance is audited (`capability.issued` with jti, role, ops, expiry), the token is not stored; a refused capability on the result gate is a `policy.denied` | P4K06 | Verified |
| Lifetime ≤ 1 h | P4K07 | Verified |
| Global role tokens keep working unchanged (the console and scripts use them) | P4K08 and the existing suites | Verified |

**Limits.**
- There is no revocation list. A token is valid until it expires, or until the capability key is replaced, which revokes every token at once (Future).
- The API still has no TLS. A bearer token sent over a non-loopback link can be copied (Assumption: loopback only, section 5).

### 10.7 Reviewer countersignature (SHOULD 7)

When a release verifies, `aegis/countersign.py` countersigns the terminal checkpoint's hash, the state, the event count and the chain head with the reviewer key (`var/keys/reviewer_ed25519.pem`, or `AEGIS_REVIEWER_KEY`). This key is separate from both the evidence key and the capability key. The exported bundle carries `reviewer_countersignature.json` and `reviewer_public_key.b64`.

`python -m aegis.verify_cli --bundle B --pubkey <broker> --require-countersignature --reviewer-pubkey <reviewer>` then requires both signatures.

| Property | Test | Label |
|---|---|---|
| A released bundle verifies with both signatures; a missing countersignature or the wrong reviewer key is refused; without the flag, verification is unchanged | `tests/test_finale_p4_countersign.py` P4S01, P4S02 | Verified |
| The broker-key forgery (the security demo's limit) verifies alone but is refused when the countersignature is required | P4S03; `scripts/security_demo.sh` step 7, a new PASS check | Verified |
| Offline countersigning on the reviewer's own machine (`python -m aegis.countersign --bundle ... --key ...`); refuses a bundle that does not verify | P4S04, P4S05 | Verified |
| Three distinct keys: evidence, capability, reviewer | P4S06 | Verified |
| Second party against a host compromise | Only when the reviewer key is off the broker host. Countersigning on release, the prototype's default, keeps it on the same host. The security demo shows the remaining limit: a forger holding both keys still succeeds. | **Partial** |
| Finale stage flow with the reviewer key off the broker's disk (`tools/venue/offhost_reviewer.sh`, P6) | The key is generated on, and only read from, the reviewer's device; the broker side pins the reviewer's public key (`--reviewer-pubkey`), never the bundle's. Tested 12 Nov 2026 with a stand-in, not a second device: a FAT image in tmpfs, loop-mounted like a USB drive. The genuine bundle verified with both keys pinned; the on-host reviewer key, an edited audit line and a key directory on the laptop's disk were refused; no key file was written under the home directory or `/tmp`. On a teammate's laptop the key never exists on the broker host. On a removable drive in the broker laptop it never lies on the broker's disk, but the broker's processes read it while countersigning, so a host already compromised at that moment can copy it. | **Partial** |

### 10.8 Mailbox quotas (SHOULD 8)

`runs.MailboxQuota` limits each tenant's outbox. A tenant over any limit is no longer served. The broker records `mailbox.quota_exceeded` once, with the quota, the limit and the observed value. The run is sealed as incomplete, so it cannot pass the release gate's completeness check. This fails closed for that tenant; the control plane and other runs are unaffected.

| Quota | Limit | Test | Label |
|---|---|---|---|
| Messages read per run | 4 × MAX_COMMITMENTS + 100 = 2,100 | `tests/test_finale_p4_quota.py` P4Q01, P4Q10 (message 21 of a 20-message limit is never processed) | Verified |
| Rate | 400 messages per 10 s | P4Q01 | Verified |
| Bytes read per run | 32 MiB, plus 64 KiB per message as before | P4Q01, P4Q12 | Verified |
| Entries present in the outbox | 512 (files, directories, anything) | P4Q01, P4Q11 | Verified |
| Normal runs unaffected | The scripted red agent sends about 10 messages plus one per attack | P4Q02, P4Q13, the podman suite | Verified |

**Limit.** The quotas bound the broker's work per tenant. They do not bound the tenant's own CPU or disk inside its container; the container limits do that (pids, memory, CPU; section 2).
