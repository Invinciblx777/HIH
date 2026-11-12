#!/usr/bin/env bash
# AegisLab finale: wake the hosted read-only demo and print how long it took. Run it about 5 minutes before the slot
# (FINALE_SCRIPT, "Before going on stage"). On Render's free plan the service sleeps after 15 minutes without traffic and the
# first request wakes it (23.6 s measured on 12 Nov 2026); a paid instance does not sleep, and this then only confirms it is up.
#
#   tools/venue/warm_render.sh            three requests to /api/lab/status: the first may be the wake-up, two warm ones after
#   tools/venue/warm_render.sh URL        another base URL
# Exit 0 if the last request returned 200 with public_demo true; 1 otherwise; 2 if there is no network at all.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$HERE/expected.env"
URL="${1:-$RENDER_URL}"
getent hosts "$(echo "$URL" | sed -E 's#^https?://([^/]+).*#\1#')" >/dev/null 2>&1 || { echo "no network: cannot resolve $URL. Use the local public demo (OFFLINE_KIT.md)."; exit 2; }
T=$(mktemp); trap 'rm -f "$T"' EXIT
for n in first warm1 warm2; do
  out=$(curl -s -o "$T" --max-time 120 -w '%{http_code} %{time_starttransfer} %{time_total}' "$URL/api/lab/status"); rc=$?
  read -r st ttfb total <<<"$out"
  pd=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("public_demo"))' "$T" 2>/dev/null || echo "?")
  printf '%s  %-5s HTTP %s  first byte %6.2f s  total %6.2f s  public_demo=%s%s\n' "$(date +%H:%M:%S)" "$n" "$st" "${ttfb:-0}" "${total:-0}" "$pd" \
    "$([ $rc -ne 0 ] && echo "  (curl exit $rc)")"
done
[ "$st" = 200 ] && [ "$pd" = True ] && { echo "Render is awake: $URL"; exit 0; }
echo "Render is NOT answering correctly. On stage, use the local public demo instead (OFFLINE_KIT.md, 'local public demo')."; exit 1
