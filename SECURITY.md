# Security policy

AegisLab is a hackathon research prototype (Hack in Hills '26, Track 04). It is not a production system and has had no third-party audit.

## Safe use

- Bind the API to loopback only (`127.0.0.1`, the default in every script). Do not expose it to a network or the internet: it starts adversarial workloads, and its role tokens are local demo tokens, not authentication.
- Never set `AEGIS_DEMO_MODE=1` outside a local demo. It returns every role token to any local caller.
- The real-model adapter is loopback-only unless `AEGIS_MODEL_ALLOW_REMOTE=1`. Keep model API keys in a file with mode 0600 (`AEGIS_MODEL_API_KEY_FILE`); never commit them.
- Use synthetic data only. The attack pack, canaries and test keys in this repository are synthetic.
- Runtime state (`var/`, including the broker signing key and demo tokens) and the virtualenv (`.venv/`) are git-ignored. Run `python3 tools/publication_scan.py --history` before publishing a fork.

## What is in scope for reports

Anything that breaks a guarantee stated in [`aegislab/THREAT_MODEL.md`](aegislab/THREAT_MODEL.md), for example: a sandbox reaching the network, the host filesystem or another sandbox; red reading blue's configuration or results before release (or the reverse); a role performing an operation the role gate should deny; an audit bundle that verifies after tampering; a canary from one run reaching another run's red output.

Known limitations that are already documented (trusted broker and signing key, global role tokens, shared host kernel, untested GPU and KV-cache isolation, base64 re-encoding not detected by the canary detector, residual timing channels) are not new findings, but evidence that quantifies them is welcome.

## How to report

Open a GitHub issue titled "Security" **without exploit details** and ask a maintainer for a private channel, or use GitHub's private vulnerability reporting if it is enabled on this repository. Please do not publish a working exploit before the team has had a chance to respond. This is a student project; there is no bug bounty.
