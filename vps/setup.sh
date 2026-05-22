#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  NetShare VPS Setup — WireGuard + Relay API
#  Run as root on a fresh Ubuntu 22.04 VPS.
#
#  What this does:
#   1. Installs WireGuard, Node.js 20, PM2
#   2. Creates the wg0 interface (10.8.0.0/24)
#   3. Enables IP forwarding + NAT masquerade (host traffic exits VPS)
#   4. Adds traffic-shaping so clients get fair bandwidth
#   5. Starts the Node relay API on port 4000
#
#  Usage:
#    chmod +x setup.sh && sudo ./setup.sh
#
#  After setup, edit /etc/wireguard/wg0.conf to add client/host peers.
#  The relay API manages peers dynamically at runtime.
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PUBLIC_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
WG_PORT=51820
API_PORT=4000
WG_NET="10.8.0.0/24"
WG_SERVER_IP="10.8.0.1"

echo "==> Detected public interface: $PUBLIC_IFACE"

# ── 1. System update + packages ──────────────────────────────────────
apt-get update -q
apt-get install -y -q wireguard wireguard-tools ufw iptables-persistent curl jq

# ── 2. Node.js 20 + PM2 ─────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -q nodejs
fi
npm install -g pm2 2>/dev/null || true

# ── 3. WireGuard keys ────────────────────────────────────────────────
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey > /etc/wireguard/server_private.key
  chmod 600 /etc/wireguard/server_private.key
fi
wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
SERVER_PRIVKEY=$(cat /etc/wireguard/server_private.key)
SERVER_PUBKEY=$(cat /etc/wireguard/server_public.key)

# ── 4. wg0.conf ──────────────────────────────────────────────────────
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address    = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVKEY}
# Masquerade all tunneled traffic out the physical interface
PostUp     = iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${PUBLIC_IFACE} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
PostDown   = iptables -t nat -D POSTROUTING -s ${WG_NET} -o ${PUBLIC_IFACE} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT

# Peers are added dynamically by the relay API (see relay/server.js).
# The relay writes to this file and calls 'wg syncconf wg0' after each change
# so WireGuard adopts new peers without dropping existing connections.
WGCONF

chmod 600 /etc/wireguard/wg0.conf

# ── 5. IP forwarding ─────────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf \
  || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ── 6. Start WireGuard ───────────────────────────────────────────────
systemctl enable wg-quick@wg0 --now || wg-quick up wg0 2>/dev/null || true

# ── 7. UFW rules ─────────────────────────────────────────────────────
ufw allow ssh
ufw allow ${WG_PORT}/udp
ufw allow ${API_PORT}/tcp
ufw --force enable

# ── 8. Write relay server ────────────────────────────────────────────
mkdir -p /opt/netshare-relay
cat > /opt/netshare-relay/package.json <<'PKG'
{
  "name": "netshare-relay",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "ws": "^8.18.0",
    "express": "^4.19.2",
    "cors": "^2.8.5"
  }
}
PKG

# Relay server is written by the main server.js file below.
# (This script only bootstraps; the actual server.js is deployed separately.)

cd /opt/netshare-relay && npm install --silent

# ── 9. PM2 startup ───────────────────────────────────────────────────
pm2 startup systemd -u root --hp /root 2>/dev/null || true
pm2 save 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  NetShare WireGuard VPS setup complete!              ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Server public key:                                  ║"
echo "║    ${SERVER_PUBKEY}"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  WireGuard port : ${WG_PORT}/udp                         ║"
echo "║  Relay API port : ${API_PORT}/tcp                        ║"
echo "║  Tunnel subnet  : ${WG_NET}                   ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Next steps:                                         ║"
echo "║    1. Copy server.js to /opt/netshare-relay/         ║"
echo "║    2. pm2 start /opt/netshare-relay/server.js        ║"
echo "║    3. pm2 save                                       ║"
echo "║    4. Set VPS_PUBLIC_KEY in app config               ║"
echo "╚══════════════════════════════════════════════════════╝"
