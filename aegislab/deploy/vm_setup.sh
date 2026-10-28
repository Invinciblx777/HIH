#!/usr/bin/env bash
# AegisLab on a fresh Ubuntu 24.04 VM (x86_64 or arm64), with LIVE runs: rootless Podman, the console behind Caddy (HTTPS).
#
#   curl -fsSL https://raw.githubusercontent.com/Invinciblx777/HIH/deploy-vm/aegislab/deploy/vm_setup.sh | sudo bash
#   (optional) sudo DOMAIN=lab.example.com BRANCH=main bash vm_setup.sh
#
# Needs ports 80 and 443 open in the cloud firewall. Without DOMAIN it uses <ip>.sslip.io, which gets a real certificate.
# The console runs as the unprivileged user "aegis"; tenants run in rootless Podman containers as that user (never root).
# Anyone can open the site read-only. Starting runs needs the operator session: the launch link printed at the end (single use).
set -Eeuo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
REPO="${REPO:-https://github.com/Invinciblx777/HIH.git}"; BRANCH="${BRANCH:-main}"; APP_USER=aegis
. /etc/os-release
[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID%%.*}" -ge 24 ] || { echo "needs Ubuntu 24.04 or newer (Python 3.11+); found ${PRETTY_NAME:-unknown}" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -qq
apt-get install -y -qq podman uidmap slirp4netns fuse-overlayfs crun python3 python3-venv python3-pip git curl ca-certificates gnupg \
  debian-keyring debian-archive-keyring apt-transport-https iptables netfilter-persistent iptables-persistent >/dev/null
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy >/dev/null
fi

echo "== service user (rootless Podman needs subuid/subgid and a lingering user manager)"
id "$APP_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$APP_USER"
grep -q "^$APP_USER:" /etc/subuid || usermod --add-subuids 100000-165535 "$APP_USER"
grep -q "^$APP_USER:" /etc/subgid || usermod --add-subgids 100000-165535 "$APP_USER"
loginctl enable-linger "$APP_USER"
APP_UID=$(id -u "$APP_USER"); systemctl start "user@$APP_UID.service"
AS() { sudo -u "$APP_USER" -H env XDG_RUNTIME_DIR="/run/user/$APP_UID" "$@"; }

echo "== code ($REPO @ $BRANCH)"
if [ -d "/home/$APP_USER/HIH/.git" ]; then AS git -C "/home/$APP_USER/HIH" fetch -q origin "$BRANCH" && AS git -C "/home/$APP_USER/HIH" checkout -q -B "$BRANCH" "origin/$BRANCH"
else AS git clone -q --branch "$BRANCH" "$REPO" "/home/$APP_USER/HIH"; fi
APP="/home/$APP_USER/HIH/aegislab"
AS python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python 3.11+ required" >&2; exit 1; }
[ -x "$APP/.venv/bin/python" ] || AS python3 -m venv "$APP/.venv"
AS "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"

echo "== rootless Podman check and sandbox image"
[ "$(AS podman info --format '{{.Host.Security.Rootless}}')" = true ] || { echo "podman is not rootless for $APP_USER" >&2; exit 1; }
AS podman pull -q docker.io/library/python:3.12-slim >/dev/null
AS env -C "$APP" AEGIS_VAR="/home/$APP_USER/var" "$APP/.venv/bin/python" -c 'from aegis import runtime, store; print("image", runtime.build_image(store.ROOT)[:19])'

echo "== console service"
IP=$(curl -fsS -4 https://ifconfig.me || curl -fsS -4 https://api.ipify.org)
DOMAIN="${DOMAIN:-$(echo "$IP" | tr . -).sslip.io}"
cat > /etc/systemd/system/aegislab.service <<UNIT
[Unit]
Description=AegisLab console (live runs, rootless Podman)
After=network-online.target user@$APP_UID.service
Wants=user@$APP_UID.service

[Service]
User=$APP_USER
WorkingDirectory=$APP
Environment=XDG_RUNTIME_DIR=/run/user/$APP_UID
Environment=AEGIS_VAR=/home/$APP_USER/var
Environment=AEGIS_CONSOLE_HOSTS=$DOMAIN
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP/.venv/bin/uvicorn aegis.console:app --host 127.0.0.1 --port 8400 --no-server-header --log-level warning --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/caddy/Caddyfile <<CADDY
$DOMAIN {
	encode gzip
	reverse_proxy 127.0.0.1:8400
}
CADDY
# Oracle Cloud Ubuntu images ship iptables rules that drop 80/443
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
netfilter-persistent save >/dev/null 2>&1 || true
systemctl daemon-reload && systemctl enable --now aegislab.service && systemctl restart caddy

echo "== waiting for the console"
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8400/api/lab/status >/dev/null 2>&1 && break; sleep 1; done
MODE=$(curl -fsS http://127.0.0.1:8400/api/lab/status | python3 -c 'import sys, json; print(json.load(sys.stdin)["mode"])')
CODE=$(AS env -C "$APP" AEGIS_VAR="/home/$APP_USER/var" "$APP/.venv/bin/python" -c 'from aegis import lab_session; print(lab_session.issue())')
echo
echo "mode: $MODE   (must say live)"
echo "site:                https://$DOMAIN"
echo "operator launch link (works once, keep it private): https://$DOMAIN/session/start?code=$CODE"
echo "new link later: sudo -u $APP_USER env -C $APP AEGIS_VAR=/home/$APP_USER/var $APP/.venv/bin/python -c 'from aegis import lab_session; print(lab_session.issue())'"
