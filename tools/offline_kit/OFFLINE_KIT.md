# AegisLab offline finale kit

Everything needed to run the finale demo with **no network**: the code, the container images, the model files, both
Python virtualenvs, Chromium for the browser checks, and the finale media. Built by `tools/offline_kit/build_kit.sh`
(finale P6, 12 Nov 2026).

## The hosted demo needs internet; the local public demo does not

- **https://aegislab-demo.onrender.com needs internet.** It is the read-only public demo, hosted on Render. With no venue
  network, it cannot be shown.
- **The offline fallback is the local public demo.** It is the same read-only mode, `AEGIS_PUBLIC_DEMO=1`, which
  `aegislab/app.py` forces on. It runs on loopback (127.0.0.1) on this laptop:

  ```bash
  cd HIH/aegislab
  AEGIS_VAR=var/console-public .venv/bin/uvicorn app:app --host 127.0.0.1 --port 8415
  # open http://127.0.0.1:8415 in the stage browser profile
  ```

  It offers what the hosted site offers: browse, replay, the independent verifier on the shipped bundles, and tamper on a
  disposable copy. It refuses session start and run creation with HTTP 403, and it has the same per-client rate limit
  (HTTP 429). There is no proxy in front of it, so `client_ip_header_present` is false locally. That is expected:
  the client address is the loopback peer.

## Contents

| Path | What | Restored to |
|---|---|---|
| `repo/HIH-main.bundle` | `git bundle` of `main` (commit in `repo/COMMIT.txt`) | `git clone` |
| `repo/HIH-p6-kit.bundle` | `git bundle` of `finale/p6-kit`: `main` plus the venue tools (`tools/venue/`) and this kit | `git clone` (default) |
| `images/aegislab-sandbox.tar` | `podman save` of `localhost/aegislab-sandbox:0.1` (ID in `images/IMAGES.txt`) | `podman load` |
| `images/python-3.12-slim-pinned.tar` | `podman save` of the digest-pinned base `python@sha256:e8a38829…` | `podman load` |
| `models/` | `qwen2.5-0.5b-instruct-q4_k_m.gguf`, `qwen2.5-1.5b-instruct-gguf/`, `llama.cpp-b11819/` (unpacked) and its release tarball, `libgomp-16.2.1-3.fc45/`, `SHA256SUMS` | used in place (`AEGIS_MODELS_DIR`) |
| `wheelhouse/` | wheels for `requirements.txt` + `constraints.txt` and `requirements-browser.txt`, CPython 3.15 and 3.14, x86_64 Linux | `pip --no-index` |
| `playwright/` | the Chromium build of Playwright 1.64.1 (`chromium-1248`, headless shell, ffmpeg) | used in place (`PLAYWRIGHT_BROWSERS_PATH`) |
| `media/` | both videos, their `.srt`, the deck `.pptx` and `.pdf`, the handout, `FINALE_SCRIPT.md`, `FINALE_JUDGE_QA.md`, `HANDOUT.md`, `SHA256SUMS` | used in place |
| `restore.sh`, `offline_check.sh` | restore, then prove it works offline | |
| `SHA256SUMS` | every file of the kit | `restore.sh` checks it first |

Nothing in the kit is a secret: no key, token or launch code. Keys are created fresh on first use.

## Restore on this laptop (Fedora, rootless Podman already set up)

```bash
bash KIT/restore.sh KIT ~/aegis-restore            # kit check, git clone, images (only if missing), venvs from the wheelhouse
source ~/aegis-restore/kit.env                      # AEGIS_MODELS_DIR and PLAYWRIGHT_BROWSERS_PATH point into the kit
bash ~/aegis-restore/HIH/tools/venue/preflight.sh --offline --models "KIT/models" --media "KIT/media"
cd ~/aegis-restore/HIH/aegislab && bash scripts/real_model_demo.sh
```

`restore.sh --ref main` checks out `main` instead of `finale/p6-kit`. `--load-images` loads both images even when they
already exist.

## Restore on a fresh Linux machine

1. Install, from the distribution's own media or a local mirror:
   - Python 3.15 or 3.14, with `venv` (the wheelhouse has wheels for both);
   - rootless Podman (`podman info` must say `rootless: true`);
   - a sub-UID range of at least 65536 for the user in `/etc/subuid` and `/etc/subgid`;
   - git.
2. `bash KIT/restore.sh KIT DEST --load-images`.
3. `source DEST/kit.env`, then `bash DEST/HIH/tools/venue/preflight.sh --offline --models KIT/models --media KIT/media`.
   - The sandbox image ID line passes, because `podman load` keeps the ID.
   - The browser-profile line fails until a stage profile exists. Use any Chromium-based browser profile there and
     edit `STAGE_PROFILE_DIR` in `tools/venue/expected.conf`.
4. Playwright's Chromium needs the usual shared libraries. On Fedora they are already present. On Debian or Ubuntu
   without network, they must come from the distribution media.
5. **The deadline D = 1400 ms was calibrated on this laptop.** On another machine, `real_model_demo.sh` still checks
   isolation, but the timing figures quoted in the deck do not transfer (FINALE_JUDGE_QA, "Deadline D").

## Proof (12 Nov 2026)

`offline_check.sh DEST OUT` first proves that the network is unreachable: pypi.org, github.com, huggingface.co and the
Render URL must all fail. It then runs:

1. `judge_demo.sh`;
2. `real_model_demo.sh`;
3. `real_model_console_check.py`, the real-model console driven by Playwright;
4. the local public demo: `/api/lab/status`, then `public_demo_check.py --local` (desktop and phone).

The results, and how the network was cut, are in `docs/finale/P6_REPORT.md` section 4.

## Size and copying

The kit size is given in P6_REPORT.md. The models make up most of it (about 1.6 GB). Copy it with
`cp -a` or `rsync -a`, then run `sha256sum -c SHA256SUMS` on the copy.
