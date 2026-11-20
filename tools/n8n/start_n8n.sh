#!/usr/bin/env bash
# AegisLab finale P16 (part B): self-hosted n8n for the incident relay, rootless Podman, reachable only on 127.0.0.1.
#
#   tools/n8n/start_n8n.sh           start (or reuse) n8n, import tools/n8n/aegis_incident.json, activate it, print the env to export
#   tools/n8n/start_n8n.sh --stop    stop and remove the container (the data volume and the incident log stay)
#
# Isolation: its own Podman network (aegis-n8n, --internal: no route out, so no telemetry and no third-party call), published only
# on 127.0.0.1:5678; --cap-drop ALL, no-new-privileges, --userns auto, memory and pid limits. The image is pinned by digest.
# The HMAC secret is generated once into ~/.config/aegislab/n8n_hmac.secret (0600, outside the repository, owned by you) and handed
# to the container as a Podman secret (copied in read-only, mode 0400, for the container's user; the host file is never chowned);
# the workflow reads it from the file, so it is in no workflow, environment variable, execution or log. The UI owner password is
# generated into ~/.config/aegislab/n8n_owner.json (0600). Incidents are appended to the volume aegis-n8n-incidents
# (read them with: podman exec aegis-n8n cat /incidents/incidents.jsonl).
set -Eeuo pipefail
IMAGE=docker.io/n8nio/n8n@sha256:eafe48609be09a2d56dd3628b29932a12c2e81a06ac5a309205652ea36146619   # n8n 2.48.6 ("stable", pulled 20 Nov 2026)
NAME=aegis-n8n; NET=aegis-n8n; PORT=5678
CONF="$HOME/.config/aegislab"; SECRET=aegis_n8n_hmac
HERE=$(cd "$(dirname "$0")" && pwd)
if [ "${1:-}" = "--stop" ]; then podman rm -f -t 5 "$NAME" >/dev/null 2>&1 || true; podman secret rm "$SECRET" >/dev/null 2>&1 || true; echo "stopped $NAME"; exit 0; fi
umask 077
mkdir -p "$CONF"
[ -s "$CONF/n8n_hmac.secret" ] || python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > "$CONF/n8n_hmac.secret"
chmod 600 "$CONF/n8n_hmac.secret"
podman image exists "$IMAGE" || { echo "n8n image not present: podman pull $IMAGE (needs approval: it is a download)" >&2; exit 1; }
podman network exists "$NET" || podman network create --internal "$NET" >/dev/null
if ! podman container exists "$NAME"; then
  podman volume exists aegis-n8n-data || podman volume create aegis-n8n-data >/dev/null
  podman volume exists aegis-n8n-incidents || podman volume create aegis-n8n-incidents >/dev/null
  podman secret rm "$SECRET" >/dev/null 2>&1 || true
  podman secret create "$SECRET" "$CONF/n8n_hmac.secret" >/dev/null
  podman run -d --name "$NAME" --label aegislab-n8n=1 --network "$NET" -p "127.0.0.1:$PORT:5678" \
    --cap-drop ALL --security-opt no-new-privileges --userns auto --memory 1g --pids-limit 512 \
    -v aegis-n8n-data:/data:U -e N8N_USER_FOLDER=/data -v aegis-n8n-incidents:/incidents:U \
    --secret "$SECRET,target=/run/aegis/hmac.secret,uid=1000,gid=1000,mode=0400" \
    -e N8N_DIAGNOSTICS_ENABLED=false -e N8N_VERSION_NOTIFICATIONS_ENABLED=false -e N8N_TEMPLATES_ENABLED=false \
    -e N8N_PERSONALIZATION_ENABLED=false -e N8N_HIRING_BANNER_ENABLED=false -e N8N_SECURE_COOKIE=false \
    -e NODE_FUNCTION_ALLOW_BUILTIN=crypto,fs -e N8N_DEFAULT_BINARY_DATA_MODE=default -e N8N_RUNNERS_ENABLED=false \
    -e N8N_HOST=127.0.0.1 -e N8N_PORT=5678 -e WEBHOOK_URL="http://127.0.0.1:$PORT/" -e GENERIC_TIMEZONE=Asia/Kolkata \
    "$IMAGE" >/dev/null
fi
for i in $(seq 1 120); do curl -sf -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -sf -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null || { podman logs --tail 30 "$NAME" >&2; echo "n8n did not become healthy" >&2; exit 1; }
podman cp "$HERE/aegis_incident.json" "$NAME:/tmp/aegis_incident.json"
for i in 1 2 3 4 5; do podman exec "$NAME" n8n import:workflow --input=/tmp/aegis_incident.json >/dev/null 2>&1 && break; sleep 5; done
podman exec "$NAME" n8n publish:workflow --id=aegisIncident001 >/dev/null 2>&1 \
  || podman exec "$NAME" n8n update:workflow --id=aegisIncident001 --active=true >/dev/null 2>&1 || true
podman restart -t 5 "$NAME" >/dev/null   # activation through the CLI takes effect at start
for i in $(seq 1 120); do curl -sf -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
if [ ! -s "$CONF/n8n_owner.json" ]; then   # UI owner for showing executions on screen (local account, generated password)
  PW=$(python3 -c 'import secrets; print("Ae9-" + secrets.token_urlsafe(18))')
  printf '{"email": "operator@aegislab.local", "password": "%s"}\n' "$PW" > "$CONF/n8n_owner.json"; chmod 600 "$CONF/n8n_owner.json"
  curl -s -m 10 -o /dev/null -X POST "http://127.0.0.1:$PORT/rest/owner/setup" -H 'Content-Type: application/json' \
    --data "{\"email\":\"operator@aegislab.local\",\"firstName\":\"Aegis\",\"lastName\":\"Operator\",\"password\":\"$PW\"}" || true
fi
echo "n8n up on http://127.0.0.1:$PORT (UI login in $CONF/n8n_owner.json); incident log: podman exec $NAME cat /incidents/incidents.jsonl" >&2
echo "export AEGIS_N8N_WEBHOOK=http://127.0.0.1:$PORT/webhook/aegis-incident AEGIS_N8N_HMAC_SECRET_FILE=$CONF/n8n_hmac.secret"
