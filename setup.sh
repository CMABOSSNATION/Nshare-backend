#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  NetShare VPS Setup — WireGuard + Node.js Admin API
#  Run as root on Ubuntu 22.04 / 24.04
#
#  After this runs:
#    • WireGuard is up on wg0, port 51820/udp
#    • Node.js relay API is running on port 4000 via PM2
#    • Admin panel: http://YOUR_IP:4000/admin
#    • User download page: http://YOUR_IP:4000/download
#
#  Usage:
#    chmod +x setup.sh
#    sudo VPS_ENDPOINT="1.2.3.4:51820" ADMIN_KEY="yourpassword" ./setup.sh
# ══════════════════════════════════════════════════════════════════════

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Config (override with env vars) ──────────────────────────────────
PUBLIC_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
WG_PORT=${WG_PORT:-51820}
API_PORT=${API_PORT:-4000}
WG_NET="10.8.0.0/24"
WG_SERVER_IP="10.8.0.1"
DEPLOY_DIR="/opt/netshare-relay"
ADMIN_KEY="${ADMIN_KEY:-change-me-NOW}"
VPS_ENDPOINT="${VPS_ENDPOINT:-}"  # Set this! e.g. "1.2.3.4:51820"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         NetShare VPS Setup — WireGuard Edition       ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Public interface : $PUBLIC_IFACE"
echo "║  WireGuard port   : $WG_PORT/udp"
echo "║  API port         : $API_PORT/tcp"
echo "║  Deploy directory : $DEPLOY_DIR"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. System packages ────────────────────────────────────────────────
echo "==> Installing packages..."
apt-get update -q
apt-get install -y -q wireguard wireguard-tools ufw iptables-persistent curl jq iproute2

# ── 2. Node.js 20 ─────────────────────────────────────────────────────
if ! command -v node &>/dev/null || [[ $(node -e "process.stdout.write(process.version.slice(1).split('.')[0])") -lt 20 ]]; then
  echo "==> Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -q nodejs
fi
echo "==> Node.js $(node -v) ready"

# PM2
npm install -g pm2 2>/dev/null || true

# ── 3. WireGuard keys ─────────────────────────────────────────────────
echo "==> Generating WireGuard keys..."
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey > /etc/wireguard/server_private.key
  chmod 600 /etc/wireguard/server_private.key
fi
wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
SERVER_PRIVKEY=$(cat /etc/wireguard/server_private.key)
SERVER_PUBKEY=$(cat /etc/wireguard/server_public.key)

# ── 4. wg0.conf ───────────────────────────────────────────────────────
echo "==> Writing /etc/wireguard/wg0.conf..."
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address    = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVKEY}
PostUp     = iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${PUBLIC_IFACE} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown   = iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${PUBLIC_IFACE} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT

# Peers are managed dynamically by the relay API.
WGCONF
chmod 600 /etc/wireguard/wg0.conf

# ── 5. IP forwarding ──────────────────────────────────────────────────
echo "==> Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ── 6. Start WireGuard ────────────────────────────────────────────────
echo "==> Starting WireGuard..."
systemctl enable wg-quick@wg0 --now 2>/dev/null || wg-quick up wg0 2>/dev/null || true

# ── 7. Firewall ───────────────────────────────────────────────────────
echo "==> Configuring UFW..."
ufw allow ssh
ufw allow ${WG_PORT}/udp
ufw allow ${API_PORT}/tcp
ufw --force enable

# ── 8. Deploy Node.js relay ───────────────────────────────────────────
echo "==> Setting up relay in ${DEPLOY_DIR}..."
mkdir -p "${DEPLOY_DIR}/admin"

# package.json
cat > "${DEPLOY_DIR}/package.json" <<'PKG'
{
  "name": "netshare-relay",
  "version": "2.0.0",
  "type": "module",
  "scripts": {
    "start": "node server.js",
    "dev":   "node --watch server.js"
  },
  "dependencies": {
    "cors":    "^2.8.5",
    "express": "^4.19.2",
    "ws":      "^8.18.0"
  }
}
PKG

# PM2 ecosystem file
cat > "${DEPLOY_DIR}/ecosystem.config.cjs" <<ECOS
module.exports = {
  apps: [{
    name: 'netshare-relay',
    script: 'server.js',
    cwd: '${DEPLOY_DIR}',
    env: {
      PORT:         '${API_PORT}',
      ADMIN_KEY:    '${ADMIN_KEY}',
      WG_IFACE:     'wg0',
      VPS_ENDPOINT: '${VPS_ENDPOINT}',
      MAX_CLIENTS:  '10',
      DATA_FILE:    '${DEPLOY_DIR}/data.json',
    },
  }],
};
ECOS

cd "${DEPLOY_DIR}"
npm install --silent

echo "==> IMPORTANT: Copy server.js, admin/index.html, download.html"
echo "    to ${DEPLOY_DIR} before starting PM2."
echo ""

# ── 9. PM2 startup ────────────────────────────────────────────────────
pm2 startup systemd -u root --hp /root 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         NetShare Setup Complete!                     ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Server public key:                                  ║"
echo "║    ${SERVER_PUBKEY}"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Next steps:                                         ║"
echo "║                                                      ║"
echo "║  1. Upload server.js, admin/index.html,              ║"
echo "║     download.html to ${DEPLOY_DIR}          ║"
echo "║                                                      ║"
echo "║  2. Edit VPS_ENDPOINT in ecosystem.config.cjs        ║"
echo "║     to your actual public IP:51820                   ║"
echo "║                                                      ║"
echo "║  3. Run:                                             ║"
echo "║       cd ${DEPLOY_DIR}                      ║"
echo "║       pm2 start ecosystem.config.cjs                 ║"
echo "║       pm2 save                                       ║"
echo "║                                                      ║"
echo "║  4. Admin panel: http://YOUR_IP:${API_PORT}/admin          ║"
echo "║  5. User page:   http://YOUR_IP:${API_PORT}/download       ║"
echo "╚══════════════════════════════════════════════════════╝"
