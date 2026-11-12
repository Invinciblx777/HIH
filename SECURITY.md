# Security policy

AegisLab is a hackathon research prototype (Hack in Hills '26, Track 04). It is not a production system and has had no third-party audit.

## Safe use

- Bind the API to loopback only (`127.0.0.1`, the default in every script). Do not expose it to a network or the internet: it starts adversarial workloads, and its role tokens are local demo tokens, not authentication.
- The only public deployment is the read-only demo: RENDER_URL on Render (primary, from `render.yaml`) and a secondary copy at https://aegislab.vercel.app. Both run `aegislab/app.py`, which forces `AEGIS_PUBLIC_DEMO=1`. In that mode the console issues no launch code and has no operator session. Live execution is off. Every state-changing request is refused (HTTP 403) except bundle verification and tampering with a disposable copy, and both are rate-limited (HTTP 429). Never put a live console (Podman plus a launch link) on a public URL. `AEGIS_PUBLIC_DEMO=1` is the only setting that lifts the loopback Host guard, and it disables every write. The live lab is never hosted: it needs a Linux machine with rootless Podman.
- The per-client verifier limit trusts exactly one header, named by `AEGIS_CLIENT_IP_HEADER`. Behind a proxy that appends to `X-Forwarded-For` instead of overwriting it (Render), set it to a header the proxy overwrites (`CF-Connecting-IP` on Render; `render.yaml` and `app.py` do this). Unset, the console uses `X-Real-IP`, then the first `X-Forwarded-For` entry, which is safe only where the proxy overwrites both (Vercel). A missing or malformed value puts the request in one shared bucket, and the global limit applies to every bucket.
- Never set `AEGIS_DEMO_MODE=1` outside a local demo. It returns every role token to any local caller.
- The real-model adapter is loopback-only unless `AEGIS_MODEL_ALLOW_REMOTE=1`. Keep model API keys in a file with mode 0600 (`AEGIS_MODEL_API_KEY_FILE`); never commit them.
- Use synthetic data only. The attack pack, canaries and test keys in this repository are synthetic.
- Runtime state (`var/`, including the broker signing key and demo tokens) and the virtualenv (`.venv/`) are git-ignored. Run `python3 tools/publication_scan.py --history` before publishing a fork.

## What is in scope for reports

Anything that breaks a guarantee stated in [`aegislab/THREAT_MODEL.md`](aegislab/THREAT_MODEL.md), for example: a sandbox reaching the network, the host filesystem or another sandbox; red reading blue's configuration or results before release (or the reverse); a role performing an operation the role gate should deny; an audit bundle that verifies after tampering; a canary from one run reaching another run's red output.

Known limitations that are already documented (trusted broker and signing key, global role tokens, shared host kernel, untested GPU and KV-cache isolation, base64 re-encoding not detected by the canary detector, residual timing channels) are not new findings, but evidence that quantifies them is welcome.

## How to report

Open a GitHub issue titled "Security" **without exploit details** and ask a maintainer for a private channel, or use GitHub's private vulnerability reporting if it is enabled on this repository. Please do not publish a working exploit before the team has had a chance to respond. This is a student project; there is no bug bounty.
