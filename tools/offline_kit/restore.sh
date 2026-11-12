#!/usr/bin/env bash
# Restore AegisLab from the offline kit, with no network. See OFFLINE_KIT.md.
#   bash restore.sh KIT_DIR DEST_DIR [--ref main|finale/p6-kit] [--load-images] [--no-podman]
# 1. sha256sum -c the kit; 2. git clone from the bundle into DEST/HIH; 3. podman load the two images (always with
# --load-images; otherwise only if missing); 4. both venvs from the wheelhouse (--no-index); 5. DEST/kit.env with
# AEGIS_MODELS_DIR and PLAYWRIGHT_BROWSERS_PATH pointing into the kit. Nothing is downloaded; pip runs with --no-index.
set -Eeuo pipefail
KIT=$(cd "${1:?KIT_DIR}" && pwd); DEST=${2:?DEST_DIR}; shift 2
REF=finale/p6-kit; LOAD=0; NOPOD=0
while [ $# -gt 0 ]; do case "$1" in --ref) REF=$2; shift ;; --load-images) LOAD=1 ;; --no-podman) NOPOD=1 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac; shift; done
step() { echo "== $(date +%H:%M:%S) $*"; }
step "1. kit integrity"; (cd "$KIT" && sha256sum --quiet -c SHA256SUMS) && echo "   SHA256SUMS OK ($(wc -l < "$KIT/SHA256SUMS") files)"
step "2. repository from the bundle ($REF)"
mkdir -p "$DEST"; DEST=$(cd "$DEST" && pwd)
B="$KIT/repo/HIH-p6-kit.bundle"; [ "$REF" = main ] && B="$KIT/repo/HIH-main.bundle"
git clone -q -b "$REF" "$B" "$DEST/HIH"
echo "   HEAD $(git -C "$DEST/HIH" rev-parse HEAD)  (kit: $(grep "^$REF=" "$KIT/repo/COMMIT.txt"))"
(cd "$DEST/HIH" && sha256sum --quiet -c MANIFEST.sha256) && echo "   MANIFEST.sha256 OK"
step "3. container images"
if [ "$NOPOD" = 1 ]; then echo "   skipped (--no-podman: e.g. inside unshare -rn, where rootless Podman cannot run)"; else
. "$DEST/HIH/tools/venue/expected.conf" 2>/dev/null || SANDBOX_IMAGE=localhost/aegislab-sandbox:0.1
if [ "$LOAD" = 1 ] || ! podman image exists "$SANDBOX_IMAGE"; then podman load -q -i "$KIT/images/aegislab-sandbox.tar"; fi
if [ "$LOAD" = 1 ] || ! podman image exists "${BASE_IMAGE:-x}"; then podman load -q -i "$KIT/images/python-3.12-slim-pinned.tar"; fi
echo "   sandbox $(podman image inspect "$SANDBOX_IMAGE" --format '{{.Id}}' | cut -c1-12) (kit: $(sed -n 's/^sandbox_image_id=//p' "$KIT/images/IMAGES.txt" | cut -c1-12))"
fi
step "4. virtualenvs from the wheelhouse (pip --no-index)"
cd "$DEST/HIH/aegislab"
python3 -m venv .venv && .venv/bin/pip install -q --no-index --find-links "$KIT/wheelhouse" -r requirements.txt -c constraints.txt
python3 -m venv .venv-browser && .venv-browser/bin/pip install -q --no-index --find-links "$KIT/wheelhouse" -r requirements-browser.txt
echo "   .venv: $(.venv/bin/pip list --format=freeze | wc -l) packages; .venv-browser: $(.venv-browser/bin/pip list --format=freeze | wc -l) packages"
step "5. environment"
cat > "$DEST/kit.env" <<ENV
export AEGIS_MODELS_DIR="$KIT/models"
export PLAYWRIGHT_BROWSERS_PATH="$KIT/playwright"
ENV
echo "   source $DEST/kit.env   (models and Chromium are used from the kit, not copied)"
echo "Restored. Next: source $DEST/kit.env && bash $DEST/HIH/tools/venue/preflight.sh --offline --models \"$KIT/models\" --media \"$KIT/media\""
