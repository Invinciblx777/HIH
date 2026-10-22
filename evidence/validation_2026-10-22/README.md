# Validation run, 22 Oct 2026

Separate from, and never overwriting, the submitted 15 Oct results (`../results.json`, `../RESULTS.md`, `../DEMO-001/`). Do not mix the two: they were produced by different code (this folder: terminal anchor, fail-closed verifier, hardened broker) and a different kernel/Podman.

## Provenance

| Item | Value |
|---|---|
| Code under test | tree hash `sha256:de2e6271f07babea7c7c35a435174911853630f807d2a77ea2d46552813d367d` (31 source files; the project is not a git repository, so this is a hash over `aegis/ sandbox/ evaluation/ scripts/ tests/ samples/` `*.py *.sh *.json`). Identical in every JSON file here (`code_revision`). Recompute: `python -c "import sys; sys.path.insert(0,'evaluation'); from revision import code_revision; print(code_revision())"` |
| Host | Fedora, kernel 7.2.11-200.fc44.x86_64, AMD Ryzen 7 7735HS (16 threads), 14 GB RAM, rootless Podman 5.8.9, crun 1.28, cgroups v2, SELinux enforcing, Python 3.14.8. The GPU (RTX 4050, 6 GB) was **not** used. cpuset controller not delegated (per-tenant CPU pinning **not** applied). |
| Desktop load | A normal desktop session was running; `loadavg` before/after is recorded in `timing*.json`. |
| Scratch state | `var/validation_2026-10-22/<experiment>/` (one fresh `AEGIS_VAR` per experiment; contains throw-away signing keys; not part of the evidence). |
| Real-model setup | llama.cpp `llama-server` build b11819 (CPU, tar.gz sha256 `98800bd7…a4f286`, binary sha256 recorded in `model_experiments.json`), `qwen2.5-0.5b-instruct-q4_k_m.gguf` (sha256 `74a4da8c…d7a9db`, matches the Hugging Face `x-linked-etag`). Downloaded to `_models/` outside the repository, bound to 127.0.0.1 on a random port with a random API key, stopped after each experiment. |

> Note (22 Oct, later): the code tree hash is now `sha256:6133ff0a…` after changes to `scripts/security_demo.py` and a new `evaluation/check_claims.py` only; the JSON files here still carry `de2e6271…` and were not re-measured. See `../../../VALIDATION_ADDENDUM_2026-10-22.md` section 8.

## Files and how to reproduce

Run from `aegislab/` inside the project virtualenv. Every command writes only to a fresh scratch `AEGIS_VAR` and to the output path shown.

| File | Command | n and what it is |
|---|---|---|
| `audit_tamper.json`, `bundles/` | `AEGIS_VAR=var/v/audit python evaluation/run_validation.py --out evidence/validation_2026-10-22 --runs 30` (~1 min) | 30 real released runs; 12 CLI tamper modes + 7 further categories × 30; the original freeze-only truncation case under old and new rules; 10 bundles × 5 variants through the CLI. Publishes `bundles/VAL-001` (must verify) and `bundles/VAL-001_TAMPERED_truncated_last3` (must fail). |
| `isolation_matrix.json` | (same command) | 212 API cases (181 expect denial, 31 expect success), 216 public GET bodies and 92 traversal cases scanned for secret markers. Container-free. |
| `timing.json`, `timing_execution_2.json` | `AEGIS_VAR=var/v/timing python evaluation/timing_eval.py --runs 20 --rtt 500 --seed 7 --out ...` (~8 min) | Two independent executions of the same experiment; 200 requests (100 refused + 100 answered) per bucket setting; mailbox RTT n=500 per condition. |
| `model_experiments.json` | `AEGIS_VAR=var/v/model python evaluation/model_experiments.py --server-dir <llama.cpp dir> --model <gguf> --out ... --sessions 20` (~4 min) | Real-model experiments M1–M6. |
| `e1_e9_rerun/` | `AEGIS_VAR=var/v/e1e9 python evaluation/run_evaluation.py --runs 10 --out evidence/validation_2026-10-22/e1_e9_rerun` (~2 min) | The original harness under the new code. Its generated `RESULTS.md` still uses the 15 Oct wording ("6 tamper types", "gap shown by last case"); the E5 numbers now cover 12 modes and the "freeze checkpoint only" case is detected 30/30 because the verifier fails closed. Its E7 line is the old **in-sample** classifier (0.47 here vs 0.57/0.56 earlier at the same setting): treat it as an illustration of that measure's instability, not as a result. |

## Verify the published bundles yourself

```bash
python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001                          # exit 0
python -m aegis.verify_cli --bundle evidence/validation_2026-10-22/bundles/VAL-001_TAMPERED_truncated_last3 # exit 1: log has 22 entries ... truncation
```

The bundle's `bundle.json` is only an index; trust comes from `terminal_anchor.json` (signed) and the public key in `broker_public_key.b64`. In a real review the reviewer pins that key out of band; here it sits next to the evidence for convenience, which means this particular check proves integrity of the files relative to that key, not authenticity of the key.

## What these results do not show

* No test here attacks the host kernel, Podman/crun, or the signing key; zero findings in finite tests is an upper bound on a rate (e.g. 0 in 80 trials → at most ~3.7% at 95% confidence), not proof.
* The 30 audit runs share one synthetic attack pack. Detection repeating 30/30 shows determinism across distinct signatures, not coverage of other workloads.
* The real-model experiments use one 0.5B model, on CPU, via llama.cpp. They test application-visible leakage, not GPU memory, KV-cache hardware state, or side channels.
* Timing: see `../../THREAT_MODEL.md` row 5 and `../../../VALIDATION_ADDENDUM_2026-10-22.md`; the two executions disagree under padding, which is itself a finding.
