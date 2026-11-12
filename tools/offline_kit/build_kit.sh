#!/usr/bin/env bash
# Finale P6 task 4: build the offline finale kit (everything needed to run the finale demo with no network).
#   tools/offline_kit/build_kit.sh KIT_DIR            needs network once (pip download); run from a checkout with .venv
# Layout: repo/ (git bundle + COMMIT.txt), images/ (podman save), models/ (_models subset + SHA256SUMS), wheelhouse/
# (cp315 and cp314 wheels for both venvs), playwright/ (Chromium cache), media/ (finale media + SHA256SUMS),
# OFFLINE_KIT.md, restore.sh, offline_check.sh, SHA256SUMS (every file of the kit).
set -Eeuo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd); APP="$REPO/aegislab"; H=$(cd "$REPO/../../.." && pwd)
KIT=${1:?KIT_DIR}; mkdir -p "$KIT"; KIT=$(cd "$KIT" && pwd)
MODELS="${AEGIS_MODELS_DIR:-$H/_models}"; MEDIA="$H/finale"
CLEAN="${KIT_SOURCE_CLONE:-$H/round2/work/finale_clean}"      # the clean clone of origin/main (task 1)
KIT_TAG="${KIT_TAG:-aegislab-finale}"                         # the release tag, bundled with main (finale P8)
. "$REPO/tools/venue/expected.conf"
log() { echo "== $(date +%H:%M:%S) $*"; }
rm -rf "$KIT"/{repo,images,models,wheelhouse,playwright,media}; mkdir -p "$KIT"/{repo,images,models,wheelhouse,playwright,media}

log "repo: git bundle of main and the tag $KIT_TAG (the clean clone) and of finale/p6-kit (this checkout: the venue tools)"
MAIN=$(git -C "$CLEAN" rev-parse main)
TAGC=$(git -C "$CLEAN" rev-parse --verify "refs/tags/$KIT_TAG^{commit}")
git -C "$CLEAN" bundle create "$KIT/repo/HIH-main.bundle" main "refs/tags/$KIT_TAG"
git -C "$REPO" bundle create "$KIT/repo/HIH-p6-kit.bundle" finale/p6-kit
P6=$(git -C "$REPO" rev-parse finale/p6-kit)
{ echo "main=$MAIN"; echo "$KIT_TAG=$TAGC"; echo "finale/p6-kit=$P6"; echo "built=$(date -Is)"; } > "$KIT/repo/COMMIT.txt"
git bundle verify "$KIT/repo/HIH-main.bundle" >/dev/null && git bundle verify "$KIT/repo/HIH-p6-kit.bundle" >/dev/null

log "images: the sandbox image and the digest-pinned base"
podman save -q -o "$KIT/images/aegislab-sandbox.tar" "$SANDBOX_IMAGE"
podman save -q -o "$KIT/images/python-3.12-slim-pinned.tar" "$BASE_IMAGE"
{ echo "sandbox_image=$SANDBOX_IMAGE"; echo "sandbox_image_id=$(podman image inspect "$SANDBOX_IMAGE" --format '{{.Id}}')"
  echo "base_image=$BASE_IMAGE"; echo "base_image_id=$(podman image inspect "$BASE_IMAGE" --format '{{.Id}}')"; } > "$KIT/images/IMAGES.txt"

log "models: both GGUFs, llama.cpp b11819 (unpacked and the release tarball), the vendored libgomp"
cp -a "$MODELS/qwen2.5-0.5b-instruct-q4_k_m.gguf" "$MODELS/llama-b11819-bin-ubuntu-x64.tar.gz" "$KIT/models/"
cp -a "$MODELS/qwen2.5-1.5b-instruct-gguf" "$MODELS/llama.cpp-b11819" "$MODELS/libgomp-16.2.1-3.fc45" "$KIT/models/"
rm -f "$KIT/models/qwen2.5-1.5b-instruct-gguf/curl.log"
(cd "$KIT/models" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
for f in MODEL SERVER LIBGOMP; do
  want=$(eval echo "\$${f}_SHA256"); got=$(sha256sum "$KIT/models/$(eval echo "\$${f}_FILE")" | cut -d' ' -f1)
  [ "$want" = "$got" ] || { echo "hash mismatch for $f"; exit 1; }
done

log "wheelhouse: requirements.txt + constraints.txt and requirements-browser.txt, for CPython 3.15 and 3.14, x86_64 Linux"
for v in 3.15 3.14; do
  "$APP/.venv/bin/pip" download -q -d "$KIT/wheelhouse" --only-binary=:all: --python-version "$v" --platform manylinux2014_x86_64 \
     --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 --platform linux_x86_64 --implementation cp \
     -r "$APP/requirements.txt" -c "$APP/constraints.txt"
  "$APP/.venv/bin/pip" download -q -d "$KIT/wheelhouse" --only-binary=:all: --python-version "$v" --platform manylinux2014_x86_64 \
     --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 --platform linux_x86_64 --implementation cp \
     -r "$APP/requirements-browser.txt"
done
"$APP/.venv/bin/pip" download -q -d "$KIT/wheelhouse" --only-binary=:all: pip   # a current pip for venvs whose ensurepip is old

log "playwright: Chromium build used by Playwright 1.64.1"
cp -a "$HOME/.cache/ms-playwright/." "$KIT/playwright/"

log "media: the R5 rebuild in finale/ (not finale/build/superseded/)"
for f in AegisLab_Finale_Judge_Cut.mp4 AegisLab_Finale_Walkthrough.mp4; do cp -a "$MEDIA/$f" "$KIT/media/"; done
mkdir -p "$KIT/media/copies_of_repo_assets"
cp -a "$MEDIA/copies_of_repo_assets/." "$KIT/media/copies_of_repo_assets/"
cp -a "$REPO/finale_package/FINALE_SCRIPT.md" "$REPO/finale_package/FINALE_JUDGE_QA.md" "$REPO/finale_package/HANDOUT.md" "$KIT/media/"
(cd "$MEDIA" && sha256sum -c --quiet <(grep -E '  (\./)?(AegisLab_Finale_(Judge_Cut|Walkthrough)\.mp4|copies_of_repo_assets/)' SHA256SUMS)) \
  || { echo "finale/ media do not match finale/SHA256SUMS"; exit 1; }
(cd "$KIT/media" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum | sed 's#  \./#  #' > SHA256SUMS)

log "docs and scripts"
cp -a "$HERE/OFFLINE_KIT.md" "$HERE/restore.sh" "$HERE/offline_check.sh" "$KIT/"
(cd "$KIT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
du -sh "$KIT"; du -sh "$KIT"/* | sort -h
log "kit built: $KIT"
