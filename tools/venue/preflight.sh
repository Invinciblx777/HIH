#!/usr/bin/env bash
# AegisLab finale: venue preflight. One PASS / FAIL / SKIP / INFO line per check; exit 0 only if nothing FAILed.
# Read-only: it starts one throw-away container (--rm, --network none) and changes nothing else.
#
#   tools/venue/preflight.sh                       every check; the Render checks report SKIP when there is no network
#   tools/venue/preflight.sh --offline             also SKIP the Render checks without trying the network
#   tools/venue/preflight.sh --models DIR          model directory (default: $AEGIS_MODELS_DIR, else <repo>/../../../_models)
#   tools/venue/preflight.sh --media DIR           finale media directory with SHA256SUMS (default: <repo>/../../../finale)
#   tools/venue/preflight.sh --record-image        print the current sandbox image ID for expected.conf, then exit
#
# Lives in tools/venue/ (not aegislab/scripts/): outside the MANIFEST-pinned folders and outside code_revision's tree, so the
# venue tooling can change up to the slot without touching pinned files or the code revision the Render site reports.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd); APP="$REPO/aegislab"
# shellcheck disable=SC1091
. "$HERE/expected.conf"
MODELS="${AEGIS_MODELS_DIR:-$REPO/../../../_models}"; MEDIA="$REPO/../../../finale"; OFFLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --models) MODELS="${2:?}"; shift ;;
    --media) MEDIA="${2:?}"; shift ;;
    --offline) OFFLINE=1 ;;
    --record-image) podman image inspect "$SANDBOX_IMAGE" --format '{{.Id}}'; exit $? ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'; else G=; R=; Y=; C=; N=; fi
FAILS=0
pass() { printf '%sPASS%s  %-24s %s\n' "$G" "$N" "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf '%sFAIL%s  %-24s %s\n' "$R" "$N" "$1" "$2"; [ -n "${3:-}" ] && printf '      %-24s -> %s\n' "" "$3"; }
skip() { printf '%sSKIP%s  %-24s %s\n' "$Y" "$N" "$1" "$2"; }
info() { printf '%sINFO%s  %-24s %s\n' "$C" "$N" "$1" "$2"; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

echo "AegisLab venue preflight  $(date '+%Y-%m-%d %H:%M %Z')  repo $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo '?')"

# 1 rootless Podman
if [ "$(timeout 20 podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = true ] &&
   timeout 60 podman run --rm --network none --user 900:900 "$SANDBOX_IMAGE" python3 -c 'print("ok")' >/dev/null 2>&1; then
  pass podman-rootless "podman $(podman --version | awk '{print $3}'), a --network none container ran"
else
  fail podman-rootless "rootless podman did not run a container" "podman info; podman system migrate; then tools/venue/reset.sh"
fi

# 2 sandbox image ID
ID=$(podman image inspect "$SANDBOX_IMAGE" --format '{{.Id}}' 2>/dev/null)
if [ -z "$ID" ]; then fail sandbox-image "$SANDBOX_IMAGE missing" "podman load -i <kit>/images/aegislab-sandbox.tar"
elif [ "$ID" = "$SANDBOX_IMAGE_ID" ]; then pass sandbox-image "${ID:0:12} as expected"
else fail sandbox-image "${ID:0:12}, expected ${SANDBOX_IMAGE_ID:0:12}" "rebuilt image: podman load the kit's image, or update expected.conf after re-running the gates"; fi
podman image exists "$BASE_IMAGE" && pass base-image "digest-pinned python:3.12-slim present" \
  || fail base-image "digest-pinned base image missing" "podman load -i <kit>/images/python-3.12-slim-pinned.tar"

# 3 model, server, libgomp hashes
for f in MODEL SERVER LIBGOMP; do
  file="$MODELS/$(eval echo "\$${f}_FILE")"; want=$(eval echo "\$${f}_SHA256")
  if [ ! -f "$file" ]; then fail "hash-${f,,}" "missing: $(basename "$file")" "restore _models from the offline kit"
  elif [ "$(sha "$file")" = "$want" ]; then pass "hash-${f,,}" "$(basename "$file") ${want:0:12}"
  else fail "hash-${f,,}" "$(basename "$file") differs from ${want:0:12}" "restore it from the offline kit"; fi
done

# 4 ports
for p in $PORTS; do
  if ss -Hltn "sport = :$p" 2>/dev/null | grep -q .; then fail "port-$p" "in use: $(ss -Hltnp "sport = :$p" 2>/dev/null | grep -o 'users:(([^)]*' | head -1 | cut -c9-)" "tools/venue/reset.sh"
  else pass "port-$p" free; fi
done

# 5 disk
for d in "$REPO" "${XDG_RUNTIME_DIR:-/tmp}" "$HOME/.local/share/containers"; do
  [ -d "$d" ] || continue
  gb=$(df -P -BG "$d" | awk 'NR==2 {gsub("G","",$4); print $4}')
  [ "$gb" -ge "$MIN_FREE_GB" ] && pass disk "${gb} GB free on $(df -P "$d" | awk 'NR==2 {print $6}')" \
    || fail disk "${gb} GB free on $(df -P "$d" | awk 'NR==2 {print $6}') (< $MIN_FREE_GB GB)" "delete old var/ state or podman image prune"
done

# 6 leftover containers
LEFT=$(podman ps -a --filter label=aegislab=1 --format '{{.Names}}' 2>/dev/null | tr '\n' ' ')
[ -z "$LEFT" ] && pass leftover-containers "none labelled aegislab=1" || fail leftover-containers "$LEFT" "tools/venue/reset.sh"

# 7 power
AC=$(cat /sys/class/power_supply/*/online 2>/dev/null | head -1); BAT=$(cat /sys/class/power_supply/BAT*/capacity 2>/dev/null | head -1)
if [ "$AC" = 1 ]; then pass power "on AC${BAT:+, battery $BAT%}"
elif [ -n "$BAT" ] && [ "$BAT" -ge "$MIN_BATTERY_PCT" ]; then pass power "on battery, $BAT% (>= $MIN_BATTERY_PCT%)"
else fail power "on battery, ${BAT:-?}%" "plug in the charger"; fi

# 8 sleep inhibited (a blocking inhibitor for sleep or idle held by this user)
if systemd-inhibit --list --no-pager 2>/dev/null | awk -v u="$(id -un)" '$4==u || $3==u' | grep -E 'sleep|idle' | grep -q block; then
  pass sleep-inhibited "a blocking sleep/idle inhibitor is held"
else
  fail sleep-inhibited "nothing blocks sleep or idle" "in a spare terminal: systemd-inhibit --what=sleep:idle:handle-lid-switch --why='AegisLab finale' sleep 3h"
fi

# 9 display and do-not-disturb (reminder; the projector is only known at the venue)
RES=$(command -v xrandr >/dev/null && xrandr --current 2>/dev/null | awk '/\*/ {print $1}' | paste -sd, -)
info display "current mode(s): ${RES:-unknown}. Mirror to the projector; 1280x720 to 1920x1080 at 100-150% zoom is tested (P6 7a)"
BANNERS=$(gsettings get org.gnome.desktop.notifications show-banners 2>/dev/null)
if [ "$BANNERS" = false ]; then pass do-not-disturb "GNOME notification banners off"
elif [ "$BANNERS" = true ]; then fail do-not-disturb "notification banners are on" "gsettings set org.gnome.desktop.notifications show-banners false  (undo: ... true)"
else info do-not-disturb "not GNOME: turn on do-not-disturb by hand"; fi

# 10 browser profile
[ -d "$STAGE_PROFILE_DIR" ] && pass browser-profile "dedicated stage profile exists" \
  || fail browser-profile "no dedicated stage profile" "$STAGE_PROFILE_CREATE  (then close it; use only this profile on stage)"

# 11 media
if [ ! -f "$MEDIA/SHA256SUMS" ]; then fail media "no SHA256SUMS in the media directory" "--media <kit>/media"
else
  bad=0; n=0
  for f in $MEDIA_FILES; do
    n=$((n + 1)); line=$(grep -E "  \\.?/?$f\$" "$MEDIA/SHA256SUMS" | head -1)
    if [ ! -f "$MEDIA/$f" ] || [ -z "$line" ] || [ "$(sha "$MEDIA/$f")" != "${line%% *}" ]; then bad=$((bad + 1)); echo "      missing or changed: $f"; fi
  done
  [ "$bad" = 0 ] && pass media "$n files present, sha256 match SHA256SUMS" || fail media "$bad of $n files missing or changed" "copy media from the offline kit"
fi

# 12, 13 Render (optional; SKIP without network)
if [ "$OFFLINE" = 1 ]; then skip render-status "--offline"; skip render-revision "--offline"
elif ! getent hosts "${RENDER_URL#https://}" >/dev/null 2>&1; then skip render-status "no network (DNS lookup failed)"; skip render-revision "no network"
else
  T=$(mktemp); code=$(curl -s -o "$T" -w '%{http_code} %{time_total}' --max-time 90 "$RENDER_URL/api/lab/status"); rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 22 ] && [ "${code%% *}" = 000 ]; then
    skip render-status "no network (curl exit $rc)"; skip render-revision "no network"
  else
    read -r st tm <<<"$code"
    chk=$(python3 - "$T" <<'PY'
import json, sys
try: d = json.load(open(sys.argv[1]))
except Exception as e: print("bad-json"); sys.exit()
print(d.get("public_demo") is True, d.get("client_ip_header_present") is True, (d.get("code_revision") or {}).get("tree_sha256", ""), (d.get("code_revision") or {}).get("files", ""))
PY
)
    read -r pd ip rrev rfiles <<<"$chk"
    if [ "$st" = 200 ] && [ "$pd" = True ] && [ "$ip" = True ]; then pass render-status "200 in ${tm}s, public_demo true, client_ip_header_present true"
    else fail render-status "HTTP $st, public_demo=$pd, client_ip_header_present=$ip" "tools/venue/warm_render.sh; if still bad, use the local public demo (OFFLINE_KIT.md)"; fi
    lrev=$(cd "$APP" && python3 -c 'import sys; sys.path.insert(0, "evaluation"); from revision import code_revision as c; r = c(); print(r["tree_sha256"], r["files"])')
    if [ -z "$rrev" ]; then fail render-revision "no code_revision in the status" "check the deploy on the Render dashboard"
    elif [ "$rrev $rfiles" = "$lrev" ]; then pass render-revision "Render serves this checkout (${rrev:7:12}, $rfiles files)"
    else fail render-revision "Render ${rrev:7:12} ($rfiles files) != local ${lrev:7:12}" "git -C $REPO status (untracked files count); git pull; or wait for the autodeploy"; fi
  fi
  rm -f "$T"
fi

echo
[ "$FAILS" = 0 ] && echo "${G}PREFLIGHT OK${N}" || echo "${R}PREFLIGHT: $FAILS check(s) FAILED${N}"
[ "$FAILS" = 0 ]
