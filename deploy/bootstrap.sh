#!/usr/bin/env bash
# Turn a fresh Ubuntu 22.04/24.04 VM (e.g. Oracle Cloud "Always Free" or a Google Cloud free-tier
# e2-micro) into a running STAGING registry with a free HTTPS address. Run from the repository:
#
#   git clone <your repo> guardian-registry && cd guardian-registry
#   sudo bash deploy/bootstrap.sh            # staging: development mode, sign-in codes shown on screen
#   sudo bash deploy/bootstrap.sh --tunnel   # ...and a public https://<random>.trycloudflare.com address
#
# What it does: installs Docker from Ubuntu's own packages, creates secrets and trial
# certificates (scripts/deploy_init.py --dev), starts Postgres + two API nodes + nginx + backups
# (deploy/docker-compose.yml), waits until ready, and with --tunnel starts a Cloudflare quick
# tunnel (free, no account) to the people's app. It never opens a database port to the internet.
#
# This is a staging setup: codes are echoed, the CA is self-signed. For production run
# deploy_init.py without --dev, fill in deploy/.env (SMS provider etc.), and use a real domain
# and certificate. Banks' mutual TLS needs the client certificate to reach nginx, which a
# Cloudflare quick tunnel does not pass on: give banks the VM's own HTTPS address instead.
set -euo pipefail

TUNNEL=0
for a in "$@"; do [ "$a" = "--tunnel" ] && TUNNEL=1; done
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f deploy/docker-compose.yml ] || { echo "run this from the repository root"; exit 1; }

echo "== Docker"
if ! command -v docker >/dev/null; then
  apt-get update -q
  apt-get install -y -q docker.io python3-venv curl
  apt-get install -y -q docker-compose-v2 || apt-get install -y -q docker-compose-plugin
  systemctl enable --now docker
fi
docker compose version >/dev/null

echo "== Swap (small free VMs have 1 GB of RAM)"
if [ "$(free -m | awk '/^Mem:/{print $2}')" -lt 2000 ] && ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q /swapfile /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

echo "== Secrets and trial certificates"
if [ ! -f deploy/secrets/db_password ]; then
  python3 -m venv /tmp/gr-init && /tmp/gr-init/bin/pip install -q "cryptography==50.0.2"
  /tmp/gr-init/bin/python scripts/deploy_init.py --dev
fi

echo "== Start the stack"
docker compose -f deploy/docker-compose.yml up -d --build --wait --wait-timeout 300
curl -fsS --cacert deploy/certs/ca.pem https://localhost:8443/readyz && echo

OPS=$(cut -d, -f1 deploy/secrets/operators)
echo
echo "Registry running on this VM at https://localhost:8443 (self-signed: trust deploy/certs/ca.pem)."
echo "Operator console: /app/admin.html, operator token for '${OPS%%:*}' is in deploy/secrets/operators"

if [ "$TUNNEL" = 1 ]; then
  echo "== Free HTTPS address (Cloudflare quick tunnel, no account)"
  if ! command -v cloudflared >/dev/null; then
    ARCH=$(dpkg --print-architecture)
    curl -fsSL -o /tmp/cloudflared.deb \
      "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
    dpkg -i /tmp/cloudflared.deb
  fi
  nohup cloudflared tunnel --no-autoupdate --url https://localhost:8443 --no-tls-verify > /var/log/gr-tunnel.log 2>&1 &
  for _ in $(seq 1 30); do
    URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' /var/log/gr-tunnel.log | head -1 || true)
    [ -n "$URL" ] && break
    sleep 2
  done
  echo "Public address: ${URL:-see /var/log/gr-tunnel.log}  (people's app: ${URL:-...}/app/)"
  echo "Quick-tunnel addresses change on restart; a free Cloudflare account gives a fixed one."
fi
