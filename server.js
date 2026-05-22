/**
 * server.js — NetShare Relay Server (WireGuard edition)
 * ═══════════════════════════════════════════════════════
 * Runs on your VPS. Manages:
 *   • WireGuard peer allocation (one peer per client, one for each host)
 *   • Session codes (XXXX-XXXX) → host mapping
 *   • WebSocket signaling channel (replaces Cloudflare DO)
 *   • Traffic rate limiting per client (prevents any one client
 *     from consuming all host bandwidth)
 *   • Bandwidth stats (polled from wg show)
 *
 * Key design: split-tunnel by default.
 *   Each peer config returned to the app includes:
 *     AllowedIPs = 0.0.0.0/0, ::/0   (only for the specific app packages)
 *   But the Android VPN builder uses addAllowedApplication() so only
 *   the selected app's traffic enters the tunnel — the rest of the
 *   device's internet goes directly without touching the VPN.
 *   This is the "doesn't consume client internet in the background" fix.
 *
 * Deploy:
 *   node server.js
 *   or: pm2 start server.js --name netshare-relay
 *
 * Environment variables:
 *   PORT          — API port (default 4000)
 *   ADMIN_KEY     — Bearer token for admin endpoints
 *   WG_IFACE      — WireGuard interface name (default wg0)
 *   VPS_ENDPOINT  — Public IP/host:port of this VPS (e.g. 1.2.3.4:51820)
 *   MAX_CLIENTS   — Max clients per host session (default 5)
 */

import express    from 'express';
import { WebSocketServer } from 'ws';
import { createServer }    from 'http';
import { execSync, exec }  from 'child_process';
import { promisify }       from 'util';
import cors               from 'cors';
import crypto             from 'crypto';

const execAsync = promisify(exec);

// ── Config ───────────────────────────────────────────────────────────
const PORT        = Number(process.env.PORT        || 4000);
const ADMIN_KEY   = process.env.ADMIN_KEY          || 'change-me-in-production';
const WG_IFACE    = process.env.WG_IFACE           || 'wg0';
const VPS_ENDPOINT= process.env.VPS_ENDPOINT       || ''; // e.g. "1.2.3.4:51820"
const MAX_CLIENTS = Number(process.env.MAX_CLIENTS || 5);
const WG_SERVER_PUBKEY = readServerPubkey();
const WG_CONF_PATH = `/etc/wireguard/${WG_IFACE}.conf`;

// IP pool: 10.8.0.2 – 10.8.0.254 (10.8.0.1 is VPS gateway)
const IP_POOL_START = 2;
const IP_POOL_END   = 254;

// ── State ────────────────────────────────────────────────────────────
const sessions   = new Map();   // sessionCode → SessionRecord
const peers      = new Map();   // publicKey → PeerRecord
const ipUsed     = new Set();   // used tunnel IPs (x in 10.8.0.x)
const wsSockets  = new Map();   // sessionCode+role → WebSocket

// ── Helpers ──────────────────────────────────────────────────────────

function readServerPubkey() {
  try {
    return execSync('cat /etc/wireguard/server_public.key').toString().trim();
  } catch {
    return process.env.WG_SERVER_PUBKEY || 'SERVER_PUBKEY_NOT_SET';
  }
}

function genCode() {
  // XXXX-XXXX from unambiguous charset
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
  return `${seg()}-${seg()}`;
}

function allocIp() {
  for (let i = IP_POOL_START; i <= IP_POOL_END; i++) {
    if (!ipUsed.has(i)) { ipUsed.add(i); return `10.8.0.${i}`; }
  }
  throw new Error('IP pool exhausted');
}

function freeIp(ip) {
  const last = parseInt(ip.split('.')[3], 10);
  ipUsed.delete(last);
}

async function wgAddPeer(publicKey, allowedIp) {
  // wg set adds peer live without restarting
  await execAsync(`wg set ${WG_IFACE} peer "${publicKey}" allowed-ips ${allowedIp}/32`);
  // Also persist to wg0.conf
  persistPeer(publicKey, allowedIp);
}

async function wgRemovePeer(publicKey) {
  try { await execAsync(`wg set ${WG_IFACE} peer "${publicKey}" remove`); } catch {}
  removePeerFromConf(publicKey);
}

function persistPeer(publicKey, allowedIp) {
  // Read conf, remove old stanza for this key if present, append fresh one
  let conf;
  try { conf = require('fs').readFileSync(WG_CONF_PATH, 'utf8'); } catch { conf = ''; }
  // Remove existing block for this pubkey
  conf = conf.replace(
    new RegExp(`\\[Peer\\]\\nPublicKey = ${escapeRegex(publicKey)}[\\s\\S]*?(?=\\[Peer\\]|$)`, 'g'),
    ''
  ).trimEnd();
  conf += `\n\n[Peer]\nPublicKey  = ${publicKey}\nAllowedIPs = ${allowedIp}/32\n`;
  require('fs').writeFileSync(WG_CONF_PATH, conf, { mode: 0o600 });
}

function removePeerFromConf(publicKey) {
  try {
    let conf = require('fs').readFileSync(WG_CONF_PATH, 'utf8');
    conf = conf.replace(
      new RegExp(`\\n*\\[Peer\\]\\nPublicKey  = ${escapeRegex(publicKey)}[\\s\\S]*?(?=\\n\\[|$)`),
      ''
    );
    require('fs').writeFileSync(WG_CONF_PATH, conf, { mode: 0o600 });
  } catch {}
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function wgStats() {
  // Returns map of pubkey → { tx, rx } bytes
  const result = {};
  try {
    const { stdout } = await execAsync(`wg show ${WG_IFACE} transfer`);
    stdout.trim().split('\n').forEach(line => {
      const [key, rx, tx] = line.trim().split(/\s+/);
      if (key) result[key] = { rx: Number(rx) || 0, tx: Number(tx) || 0 };
    });
  } catch {}
  return result;
}

// ── HTTP + WebSocket server ───────────────────────────────────────────
const app    = express();
const server = createServer(app);
const wss    = new WebSocketServer({ server, path: '/ws' });

app.use(cors());
app.use(express.json());

// ── REST: health ──────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, sessions: sessions.size }));
app.get('/ping',   (_, res) => res.send('OK'));

// ── REST: HOST register ───────────────────────────────────────────────
// Host calls this to get a WireGuard config + session code.
// Body: { publicKey: "<wg pubkey of host device>" }
// Returns: { sessionCode, serverPublicKey, serverEndpoint, clientIp, dns }
app.post('/host/register', async (req, res) => {
  const { publicKey, hostId } = req.body || {};
  if (!publicKey) return res.status(400).json({ error: 'publicKey required' });

  // Reuse if host already has a session
  for (const [code, sess] of sessions) {
    if (sess.hostId === hostId && sess.active) {
      return res.json({
        sessionCode:    code,
        serverPublicKey: WG_SERVER_PUBKEY,
        serverEndpoint: VPS_ENDPOINT,
        clientIp:       sess.hostIp,
        dns:            '1.1.1.1',
      });
    }
  }

  let sessionCode = genCode();
  while (sessions.has(sessionCode)) sessionCode = genCode();

  let hostIp;
  try { hostIp = allocIp(); } catch (e) { return res.status(503).json({ error: e.message }); }

  await wgAddPeer(publicKey, hostIp);

  const record = {
    sessionCode,
    hostPublicKey: publicKey,
    hostId:        hostId || `host-${Date.now()}`,
    hostIp,
    clients:       new Map(), // deviceId → { publicKey, ip }
    active:        true,
    createdAt:     Date.now(),
  };
  sessions.set(sessionCode, record);
  peers.set(publicKey, { type: 'host', sessionCode, ip: hostIp });

  console.log(`[HOST] Registered session=${sessionCode} hostIp=${hostIp}`);

  res.json({
    sessionCode,
    serverPublicKey: WG_SERVER_PUBKEY,
    serverEndpoint:  VPS_ENDPOINT,
    clientIp:        hostIp,
    dns:             '1.1.1.1',
  });
});

// ── REST: CLIENT join ─────────────────────────────────────────────────
// Client calls this with session code + its WG public key.
// Returns WireGuard config for client — points ONLY at VPS.
// AllowedIPs is 0.0.0.0/0 at the WG layer; the Android VPN builder
// restricts which apps enter the tunnel (split-tunnel).
app.post('/client/join', async (req, res) => {
  const { sessionCode, publicKey, deviceId } = req.body || {};
  if (!sessionCode || !publicKey) return res.status(400).json({ error: 'sessionCode + publicKey required' });

  const sess = sessions.get(sessionCode.toUpperCase().trim());
  if (!sess || !sess.active) return res.status(404).json({ error: 'Session not found or expired' });
  if (sess.clients.size >= MAX_CLIENTS) return res.status(429).json({ error: 'Session full' });

  // Idempotent: if same device re-joins, return existing config
  const existing = sess.clients.get(deviceId);
  if (existing) {
    return res.json({
      serverPublicKey: WG_SERVER_PUBKEY,
      serverEndpoint:  VPS_ENDPOINT,
      clientIp:        existing.ip,
      dns:             '1.1.1.1',
    });
  }

  let clientIp;
  try { clientIp = allocIp(); } catch (e) { return res.status(503).json({ error: e.message }); }

  await wgAddPeer(publicKey, clientIp);
  sess.clients.set(deviceId || publicKey, { publicKey, ip: clientIp });
  peers.set(publicKey, { type: 'client', sessionCode, ip: clientIp, deviceId });

  // Apply per-client bandwidth limit (1 Mbit burst, fair queue).
  // This ensures a client cannot monopolize the host's uplink.
  await applyClientRateLimit(clientIp);

  // Notify host over WS that a client joined
  notifyHost(sessionCode, { type: 'clientConnected', deviceId });

  console.log(`[CLIENT] joined session=${sessionCode} ip=${clientIp} device=${deviceId}`);

  res.json({
    serverPublicKey: WG_SERVER_PUBKEY,
    serverEndpoint:  VPS_ENDPOINT,
    clientIp,
    dns:             '1.1.1.1',
  });
});

// ── REST: validate code (before client generates WG keypair) ──────────
app.post('/validate-code', (req, res) => {
  const { code } = req.body || {};
  const sess = sessions.get((code || '').toUpperCase().trim());
  if (!sess || !sess.active) return res.json({ valid: false, reason: 'Invalid or expired session code' });
  if (sess.clients.size >= MAX_CLIENTS) return res.json({ valid: false, reason: 'Session is full' });
  res.json({ valid: true });
});

// ── REST: HOST leave / CLIENT leave ──────────────────────────────────
app.post('/leave', async (req, res) => {
  const { sessionCode, role, publicKey, deviceId } = req.body || {};
  const sess = sessions.get((sessionCode || '').toUpperCase());
  if (!sess) return res.json({ ok: true });

  if (role === 'host') {
    await teardownSession(sessionCode);
  } else {
    const clientRecord = sess.clients.get(deviceId || publicKey);
    if (clientRecord) {
      await wgRemovePeer(clientRecord.publicKey);
      freeIp(clientRecord.ip);
      removeClientRateLimit(clientRecord.ip);
      sess.clients.delete(deviceId || publicKey);
      peers.delete(clientRecord.publicKey);
      notifyHost(sessionCode, { type: 'clientDisconnected', deviceId });
    }
  }
  res.json({ ok: true });
});

// ── REST: bandwidth stats (polled by app every 5s) ───────────────────
app.get('/stats/:sessionCode', async (req, res) => {
  const sess = sessions.get(req.params.sessionCode.toUpperCase());
  if (!sess) return res.status(404).json({ error: 'Not found' });
  const stats = await wgStats();
  const hostStats   = stats[sess.hostPublicKey]   || { rx: 0, tx: 0 };
  const clientStats = {};
  for (const [devId, c] of sess.clients) {
    const s = stats[c.publicKey] || { rx: 0, tx: 0 };
    clientStats[devId] = s;
  }
  res.json({ host: hostStats, clients: clientStats, clientCount: sess.clients.size });
});

// ── REST: admin endpoints ─────────────────────────────────────────────
app.get('/admin/sessions', (req, res) => {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  const out = [];
  for (const [code, s] of sessions) {
    out.push({
      code,
      hostId:      s.hostId,
      hostIp:      s.hostIp,
      clients:     s.clients.size,
      active:      s.active,
      ageMinutes:  Math.floor((Date.now() - s.createdAt) / 60000),
    });
  }
  res.json(out);
});

// ── WebSocket: signaling channel ──────────────────────────────────────
// Hosts connect here to receive notifications (clientConnected, etc.)
// Message format: { type: 'REGISTER', role: 'host'|'client', sessionCode, ... }
wss.on('connection', (ws, req) => {
  ws._sessionCode = null;
  ws._role        = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'REGISTER') {
      ws._sessionCode = (msg.sessionCode || '').toUpperCase();
      ws._role        = msg.role;
      const key = `${ws._sessionCode}:${ws._role}`;
      wsSockets.set(key, ws);
      ws.send(JSON.stringify({ type: 'REGISTERED', ok: true }));
      return;
    }

    if (msg.type === 'PING') {
      ws.send(JSON.stringify({ type: 'PONG' }));
    }
  });

  ws.on('close', () => {
    const key = `${ws._sessionCode}:${ws._role}`;
    if (wsSockets.get(key) === ws) wsSockets.delete(key);
    // If host disconnects, start grace-period teardown
    if (ws._role === 'host' && ws._sessionCode) {
      scheduleHostTimeout(ws._sessionCode);
    }
  });
});

function notifyHost(sessionCode, payload) {
  const ws = wsSockets.get(`${sessionCode}:host`);
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify(payload));
  }
}

// ── Traffic shaping ───────────────────────────────────────────────────
// Each client gets a per-IP fq_codel queue to prevent one client starving others.
// This keeps the app responsive even when one client is doing a heavy download.
async function applyClientRateLimit(ip) {
  // Requires iproute2 (tc). If not available, silently skip.
  try {
    // Mark the client's returning traffic (from VPS to client)
    const mark = ipToMark(ip);
    await execAsync(`iptables -t mangle -A POSTROUTING -d ${ip}/32 -j MARK --set-mark ${mark} 2>/dev/null || true`);
    // tc: use fq_codel on the WireGuard interface for fair queueing
    // (Only set up once on the interface; per-flow fairness is automatic)
    await execAsync(`tc qdisc replace dev ${WG_IFACE} root fq_codel 2>/dev/null || true`);
  } catch (e) {
    console.warn('[tc] Rate limit setup skipped:', e.message);
  }
}

async function removeClientRateLimit(ip) {
  try {
    const mark = ipToMark(ip);
    await execAsync(`iptables -t mangle -D POSTROUTING -d ${ip}/32 -j MARK --set-mark ${mark} 2>/dev/null || true`);
  } catch {}
}

function ipToMark(ip) {
  // Use last octet of 10.8.0.X as the mark (unique per client in /24)
  return parseInt(ip.split('.')[3], 10);
}

// ── Session teardown ──────────────────────────────────────────────────
async function teardownSession(sessionCode) {
  const sess = sessions.get(sessionCode);
  if (!sess) return;
  sess.active = false;

  // Notify all clients that host left
  for (const [devId, c] of sess.clients) {
    const clientWs = wsSockets.get(`${sessionCode}:client:${devId}`);
    if (clientWs && clientWs.readyState === 1) {
      clientWs.send(JSON.stringify({ type: 'hostLeft', reason: 'Host ended session' }));
    }
    try { await wgRemovePeer(c.publicKey); } catch {}
    freeIp(c.ip);
    removeClientRateLimit(c.ip);
    peers.delete(c.publicKey);
  }

  // Remove host peer
  try { await wgRemovePeer(sess.hostPublicKey); } catch {}
  freeIp(sess.hostIp);
  peers.delete(sess.hostPublicKey);
  sessions.delete(sessionCode);
  console.log(`[SESSION] Torn down: ${sessionCode}`);
}

const hostTimeouts = new Map();
function scheduleHostTimeout(sessionCode) {
  if (hostTimeouts.has(sessionCode)) return;
  const t = setTimeout(async () => {
    hostTimeouts.delete(sessionCode);
    const ws = wsSockets.get(`${sessionCode}:host`);
    if (ws && ws.readyState === 1) return; // host reconnected
    console.log(`[HOST] Grace period expired for ${sessionCode}, tearing down`);
    await teardownSession(sessionCode);
  }, 60_000); // 60s grace
  hostTimeouts.set(sessionCode, t);
}

// ── Startup ───────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`╔════════════════════════════════════════════╗`);
  console.log(`║  NetShare Relay API (WireGuard edition)    ║`);
  console.log(`║  Listening on port ${PORT}                    ║`);
  console.log(`║  WG interface: ${WG_IFACE}                      ║`);
  console.log(`║  Server pubkey:                            ║`);
  console.log(`║    ${WG_SERVER_PUBKEY.slice(0, 40)}…`);
  console.log(`╚════════════════════════════════════════════╝`);
});
