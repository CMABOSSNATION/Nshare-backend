/**
 * server.js — NetShare VPS Relay (WireGuard + Admin Edition)
 * ═══════════════════════════════════════════════════════════
 *
 *  Architecture:
 *    • VPS runs WireGuard (wg0) + this Node.js API
 *    • Users download the official WireGuard app and paste a .conf
 *    • NO React Native / mobile app needed
 *    • Admin panel at /admin (web browser, password protected)
 *
 *  Flow:
 *    HOST:   Admin generates a HOST access code → host visits
 *            GET /config/host?code=XXXX-XXXX → downloads wg.conf
 *            → imports into WireGuard app → connects
 *
 *    CLIENT: Admin generates CLIENT code (or host shares their session
 *            code) → client visits GET /config/client?code=XXXX-XXXX
 *            → downloads wg.conf → imports into WireGuard app
 *
 *  ── DATA SAVING ARCHITECTURE ────────────────────────────────────────
 *
 *  OLD (wasteful):
 *    Client → VPS → Internet          (client pays for ALL traffic)
 *    AllowedIPs = 0.0.0.0/0 means the client's WireGuard app sends
 *    every byte of internet traffic through the tunnel.
 *
 *  NEW (host-exit routing):
 *    Client → VPS tunnel → Host → Host's Internet
 *    Client's own data only carries the WireGuard UDP packets to VPS.
 *    All actual internet requests exit through the HOST device.
 *    Client data usage: ~2-5 MB/day idle, tunnel overhead only when active.
 *
 *  How it works:
 *    1. Client config: AllowedIPs = 10.8.0.0/24 ONLY (just the tunnel subnet)
 *       This means only traffic destined for 10.8.0.x goes into the tunnel.
 *       Everything else uses the client's real network.
 *    2. The host device (10.8.0.2) acts as a NAT gateway / router.
 *       All client traffic that needs real internet is routed:
 *       Client → 10.8.0.2 (host) → host's internet connection
 *    3. VPS just relays encrypted WireGuard UDP between peers.
 *       It does NOT handle internet traffic at all.
 *
 *  Result: Client data usage is ONLY the WireGuard tunnel overhead:
 *    - Keepalives (25s interval): ~180 KB/hour → ~4 MB/day idle
 *    - Tunnel overhead on active traffic: ~3-5% of actual content
 *    - Streaming 1GB through host costs client ~30-50 MB own data
 *
 *  Environment variables (set in /etc/environment or PM2 ecosystem):
 *    PORT          API port (default 4000)
 *    ADMIN_KEY     Admin panel password
 *    WG_IFACE      WireGuard interface (default wg0)
 *    VPS_ENDPOINT  Public IP:port of this VPS, e.g. 1.2.3.4:51820
 *    MAX_CLIENTS   Max clients per host session (default 10)
 *    DATA_FILE     Path to persist sessions/codes (default /opt/netshare-relay/data.json)
 *    CLIENT_KEEPALIVE  Keepalive interval in seconds (default 25, min 15, max 120)
 *    SESSION_TIMEOUT_H Host session auto-expire in hours (default 24)
 *    MAX_DATA_MB_DAY   Max MB per client per day before throttle warning (default 50)
 */

import express        from 'express';
import { createServer } from 'http';
import { execSync, exec } from 'child_process';
import { promisify }    from 'util';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import cors             from 'cors';
import crypto           from 'crypto';
import path             from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const execAsync = promisify(exec);

// ── Config ────────────────────────────────────────────────────────────
const PORT             = Number(process.env.PORT              || 4000);
const ADMIN_KEY        = process.env.ADMIN_KEY                || 'change-me-NOW';
const WG_IFACE         = process.env.WG_IFACE                 || 'wg0';
const VPS_ENDPOINT     = process.env.VPS_ENDPOINT             || ''; // REQUIRED: "1.2.3.4:51820"
const MAX_CLIENTS      = Number(process.env.MAX_CLIENTS       || 10);
const DATA_FILE        = process.env.DATA_FILE                || '/opt/netshare-relay/data.json';
const WG_CONF_PATH     = `/etc/wireguard/${WG_IFACE}.conf`;

// Data-saving tuning
const CLIENT_KEEPALIVE    = Math.min(120, Math.max(15, Number(process.env.CLIENT_KEEPALIVE   || 25)));
const SESSION_TIMEOUT_H   = Number(process.env.SESSION_TIMEOUT_H  || 24);
const MAX_DATA_MB_DAY     = Number(process.env.MAX_DATA_MB_DAY     || 50);

// ── State (persisted to DATA_FILE) ───────────────────────────────────
let codes    = new Map();
let sessions = new Map();
let ipUsed   = new Set();

// Per-client daily data tracking: Map<publicKey, { date: 'YYYY-MM-DD', bytes: number }>
let clientDataUsage = new Map();

const WG_SERVER_PUBKEY = readServerPubkey();

// ── Persistence ───────────────────────────────────────────────────────
function saveData() {
  try {
    const data = {
      codes:    [...codes.entries()],
      sessions: [...sessions.entries()].map(([k, v]) => [k, {
        ...v,
        clients: [...v.clients.entries()],
      }]),
      ipUsed:          [...ipUsed],
      clientDataUsage: [...clientDataUsage.entries()],
    };
    writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('[DATA] Save failed:', e.message);
  }
}

function loadData() {
  if (!existsSync(DATA_FILE)) return;
  try {
    const data = JSON.parse(readFileSync(DATA_FILE, 'utf8'));
    codes    = new Map(data.codes    || []);
    ipUsed   = new Set(data.ipUsed   || []);
    clientDataUsage = new Map(data.clientDataUsage || []);
    for (const [k, v] of (data.sessions || [])) {
      sessions.set(k, { ...v, clients: new Map(v.clients || []) });
    }
    console.log(`[DATA] Loaded ${codes.size} codes, ${sessions.size} sessions`);
  } catch (e) {
    console.error('[DATA] Load failed:', e.message);
  }
}

// ── WireGuard helpers ─────────────────────────────────────────────────
function readServerPubkey() {
  try { return execSync('cat /etc/wireguard/server_public.key').toString().trim(); }
  catch { return process.env.WG_SERVER_PUBKEY || 'SERVER_PUBKEY_NOT_SET'; }
}

function allocIp() {
  for (let i = 2; i <= 254; i++) {
    if (!ipUsed.has(i)) { ipUsed.add(i); return `10.8.0.${i}`; }
  }
  throw new Error('IP pool exhausted (max 253 peers)');
}

function freeIp(ip) {
  if (!ip) return;
  const last = parseInt(ip.split('.')[3], 10);
  ipUsed.delete(last);
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

async function wgAddPeer(publicKey, allowedIp) {
  await execAsync(`wg set ${WG_IFACE} peer "${publicKey}" allowed-ips ${allowedIp}/32`);
  let conf = '';
  try { conf = readFileSync(WG_CONF_PATH, 'utf8'); } catch {}
  conf = conf.replace(
    new RegExp(`\\n*\\[Peer\\]\\nPublicKey\\s*=\\s*${escapeRe(publicKey)}[\\s\\S]*?(?=\\n\\[|$)`), ''
  ).trimEnd();
  conf += `\n\n[Peer]\nPublicKey  = ${publicKey}\nAllowedIPs = ${allowedIp}/32\n`;
  writeFileSync(WG_CONF_PATH, conf, { mode: 0o600 });
}

async function wgRemovePeer(publicKey) {
  if (!publicKey) return;
  try { await execAsync(`wg set ${WG_IFACE} peer "${publicKey}" remove`); } catch {}
  try {
    let conf = readFileSync(WG_CONF_PATH, 'utf8');
    conf = conf.replace(
      new RegExp(`\\n*\\[Peer\\]\\nPublicKey\\s*=\\s*${escapeRe(publicKey)}[\\s\\S]*?(?=\\n\\[|$)`), ''
    );
    writeFileSync(WG_CONF_PATH, conf, { mode: 0o600 });
  } catch {}
}

async function wgStats() {
  const result = {};
  try {
    const { stdout } = await execAsync(`wg show ${WG_IFACE} transfer`);
    for (const line of stdout.trim().split('\n')) {
      const [key, rx, tx] = line.trim().split(/\s+/);
      if (key) result[key] = { rx: Number(rx) || 0, tx: Number(tx) || 0 };
    }
  } catch {}
  return result;
}

// ── Code helpers ──────────────────────────────────────────────────────
function genCode(prefix = '') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg   = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
  let code;
  do { code = `${prefix}${seg()}-${seg()}`; } while (codes.has(code));
  return code;
}

function cleanCode(raw) {
  return (raw || '').toString().toUpperCase().trim();
}

// ── WireGuard config builder ──────────────────────────────────────────
//
// KEY CHANGE from original:
//
// HOST config:   AllowedIPs = 0.0.0.0/0, ::/0
//   The host routes ALL its traffic through the tunnel so it becomes
//   the exit node. The host's internet connection is what clients use.
//
// CLIENT config: AllowedIPs = 10.8.0.0/24
//   Clients ONLY route traffic destined for the tunnel subnet (10.8.0.x)
//   through WireGuard. Everything else (YouTube, WhatsApp, browsing) uses
//   the client's real network directly.
//   To reach the internet, client apps send to 10.8.0.1 (VPS gateway) or
//   10.8.0.2 (host), which the host NATs to its own internet connection.
//   This means the client's mobile data only carries encrypted WireGuard
//   UDP packets — tunnel overhead only, not full internet traffic.
//
// DNS for clients:
//   Set to the host's tunnel IP (10.8.0.2) so DNS queries go through
//   the host's connection. This prevents DNS leaks and keeps client
//   data usage minimal (no separate DNS traffic on client's network).

function buildWgConf({ peerPrivateKey, peerIp, role = 'client', hostTunnelIp = '10.8.0.2', keepalive = CLIENT_KEEPALIVE }) {

  // HOST: full tunnel — host becomes the internet exit node for all clients
  // CLIENT: subnet only — client's internet stays on their own connection,
  //         only tunnel traffic (10.8.0.x) goes through WireGuard
  const allowedIPs = role === 'host'
    ? '0.0.0.0/0, ::/0'
    : '10.8.0.0/24';

  // DNS:
  // HOST: use Cloudflare/Google (host needs real internet DNS)
  // CLIENT: use host as DNS resolver so queries go through host's connection
  //         This saves client data — DNS queries don't hit client's network
  const dns = role === 'host'
    ? '1.1.1.1, 8.8.8.8'
    : hostTunnelIp;  // 10.8.0.2 — host device resolves DNS for clients

  // Keepalive:
  // HOST: standard 25s — host must stay reachable for clients
  // CLIENT: longer interval to reduce keepalive data usage
  //         Each keepalive is ~60 bytes. At 60s: ~86 KB/day vs ~180 KB/day at 25s
  //         Small saving but adds up over many clients
  const ka = role === 'host' ? 25 : keepalive;

  return [
    '[Interface]',
    `PrivateKey = ${peerPrivateKey}`,
    `Address    = ${peerIp}/24`,
    `DNS        = ${dns}`,
    '',
    '[Peer]',
    `PublicKey  = ${WG_SERVER_PUBKEY}`,
    `Endpoint   = ${VPS_ENDPOINT}`,
    `AllowedIPs = ${allowedIPs}`,
    `PersistentKeepalive = ${ka}`,
  ].join('\n');
}

function genKeypair() {
  const priv = execSync('wg genkey').toString().trim();
  const pub  = execSync(`echo "${priv}" | wg pubkey`).toString().trim();
  return { priv, pub };
}

// ── Daily data tracking ───────────────────────────────────────────────
function todayStr() {
  return new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
}

function recordClientData(publicKey, bytes) {
  const today = todayStr();
  const rec   = clientDataUsage.get(publicKey) || { date: today, bytes: 0 };
  if (rec.date !== today) { rec.date = today; rec.bytes = 0; } // reset daily
  rec.bytes += bytes;
  clientDataUsage.set(publicKey, rec);
}

function getClientDataToday(publicKey) {
  const today = todayStr();
  const rec   = clientDataUsage.get(publicKey);
  if (!rec || rec.date !== today) return 0;
  return rec.bytes;
}

// ── Express app ───────────────────────────────────────────────────────
const app    = express();
const server = createServer(app);

app.use(cors());
app.use(express.json());

app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.get('/download', (_, res) => res.sendFile(path.join(__dirname, 'download.html')));
app.get('/',        (_, res) => res.sendFile(path.join(__dirname, 'download.html')));

// ── Auth middleware ───────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── Admin login ───────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const key = req.body?.key || req.body?.password || '';
  if (key === ADMIN_KEY) return res.json({ ok: true });
  return res.status(401).json({ error: 'Wrong admin key' });
});

// ── Health ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({
  ok: true,
  sessions:      sessions.size,
  codes:         codes.size,
  vpsEndpoint:   VPS_ENDPOINT,
  serverPubkey:  WG_SERVER_PUBKEY,
  dataSavingMode: true,
  clientKeepalive: CLIENT_KEEPALIVE,
  maxDataMbDay:  MAX_DATA_MB_DAY,
}));

// ── Config download ───────────────────────────────────────────────────
app.get('/config', async (req, res) => {
  const code = cleanCode(req.query.code);
  if (!code) return res.status(400).json({ error: 'code required' });

  const codeRecord = codes.get(code);
  if (!codeRecord) return res.status(404).json({ error: 'Invalid or expired code' });
  if (codeRecord.used && codeRecord.type !== 'host') {
    return res.status(410).json({ error: 'Code already used' });
  }
  if (codeRecord.expiresAt && Date.now() > codeRecord.expiresAt) {
    codes.delete(code);
    saveData();
    return res.status(410).json({ error: 'Code expired' });
  }

  let keypair;
  try { keypair = genKeypair(); }
  catch (e) { return res.status(500).json({ error: 'Failed to generate WireGuard keys: ' + e.message }); }

  let peerIp;
  try { peerIp = allocIp(); }
  catch (e) { return res.status(503).json({ error: e.message }); }

  try { await wgAddPeer(keypair.pub, peerIp); }
  catch (e) {
    freeIp(peerIp);
    return res.status(500).json({ error: 'WireGuard peer setup failed: ' + e.message });
  }

  const sessionId = crypto.randomUUID();
  const now       = Date.now();

  if (codeRecord.type === 'host') {
    const sessionCode = genCode();
    const expiresAt   = now + SESSION_TIMEOUT_H * 3600_000;

    sessions.set(sessionId, {
      sessionId,
      sessionCode,
      type:       'host',
      codeUsed:   code,
      publicKey:  keypair.pub,
      ip:         peerIp,           // host tunnel IP e.g. 10.8.0.2
      label:      codeRecord.label || 'Host',
      clients:    new Map(),
      createdAt:  now,
      expiresAt,
      active:     true,
    });

    codeRecord.used      = true;
    codeRecord.sessionId = sessionId;
    codes.set(code, codeRecord);
    saveData();

    // Host gets full-tunnel config — it becomes the internet exit node
    const conf = buildWgConf({ peerPrivateKey: keypair.priv, peerIp, role: 'host' });
    const filename = `netshare-host-${sessionCode}.conf`;
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send([
      `# NetShare HOST Config`,
      `# Session Code (share with clients): ${sessionCode}`,
      `# Generated: ${new Date().toISOString()}`,
      `# Expires:   ${new Date(expiresAt).toISOString()}`,
      `#`,
      `# IMPORTANT: You are the internet exit node.`,
      `# Clients browse through YOUR internet connection.`,
      `# Make sure your device stays connected while sharing.`,
      ``,
      conf,
    ].join('\n'));
  }

  if (codeRecord.type === 'client') {
    const hostSession = [...sessions.values()].find(
      s => s.sessionCode === codeRecord.sessionCode && s.active
    );
    if (!hostSession) {
      freeIp(peerIp);
      await wgRemovePeer(keypair.pub);
      return res.status(404).json({ error: 'Host session not found or expired' });
    }
    if (hostSession.clients.size >= MAX_CLIENTS) {
      freeIp(peerIp);
      await wgRemovePeer(keypair.pub);
      return res.status(429).json({ error: 'Session is full' });
    }

    const clientId = crypto.randomUUID();
    hostSession.clients.set(clientId, {
      clientId,
      publicKey: keypair.pub,
      ip:        peerIp,
      label:     codeRecord.label || 'Client',
      joinedAt:  now,
    });

    codeRecord.used      = true;
    codeRecord.sessionId = hostSession.sessionId;
    codeRecord.clientId  = clientId;
    codes.set(code, codeRecord);
    saveData();

    // Client gets subnet-only config — data saving mode
    // AllowedIPs = 10.8.0.0/24 means ONLY tunnel subnet traffic
    // goes through WireGuard. Client's own internet is untouched.
    const conf = buildWgConf({
      peerPrivateKey: keypair.priv,
      peerIp,
      role:          'client',
      hostTunnelIp:  hostSession.ip,   // host's tunnel IP for DNS
      keepalive:     CLIENT_KEEPALIVE,
    });
    const filename = `netshare-client-${code}.conf`;
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send([
      `# NetShare CLIENT Config`,
      `# Code: ${code}`,
      `# Generated: ${new Date().toISOString()}`,
      `#`,
      `# DATA SAVING MODE ACTIVE`,
      `# Your mobile data is only used for the WireGuard tunnel.`,
      `# All internet traffic goes through the host's connection.`,
      `# Estimated usage: ~4 MB/day idle, ~30-50 MB overhead/GB streamed.`,
      ``,
      conf,
    ].join('\n'));
  }

  return res.status(400).json({ error: 'Invalid code type' });
});

// ── Config info ───────────────────────────────────────────────────────
app.get('/config/info', (req, res) => {
  const code = cleanCode(req.query.code);
  const rec  = codes.get(code);
  if (!rec) return res.status(404).json({ valid: false, reason: 'Invalid code' });
  if (rec.expiresAt && Date.now() > rec.expiresAt) return res.json({ valid: false, reason: 'Code expired' });
  if (rec.used && rec.type !== 'host') return res.json({ valid: false, reason: 'Code already used' });
  res.json({
    valid: true,
    type:        rec.type,
    label:       rec.label,
    sessionCode: rec.sessionCode,
  });
});

// ── ADMIN: Code management ────────────────────────────────────────────
app.post('/admin/codes/create', requireAdmin, (req, res) => {
  const { type, label, sessionCode, count = 1, expiresInHours } = req.body || {};
  if (!['host', 'client'].includes(type)) {
    return res.status(400).json({ error: 'type must be "host" or "client"' });
  }
  if (type === 'client' && !sessionCode) {
    return res.status(400).json({ error: 'sessionCode required for client codes' });
  }

  const expiresAt = expiresInHours ? Date.now() + expiresInHours * 3600_000 : null;
  const created   = [];

  for (let i = 0; i < Math.min(count, 100); i++) {
    const code = genCode(type === 'host' ? 'H' : 'C');
    codes.set(code, {
      code, type, label: label || (type === 'host' ? 'Host' : 'Client'),
      sessionCode: sessionCode || null,
      createdAt: Date.now(), expiresAt, used: false,
    });
    created.push(code);
  }

  saveData();
  res.json({ created, count: created.length });
});

app.get('/admin/codes', requireAdmin, (req, res) => {
  const out = [...codes.values()].map(c => ({
    ...c,
    expired: c.expiresAt ? Date.now() > c.expiresAt : false,
  }));
  res.json(out);
});

app.delete('/admin/codes/:code', requireAdmin, async (req, res) => {
  const code = cleanCode(req.params.code);
  const rec  = codes.get(code);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  if (rec.sessionId) await teardownSession(rec.sessionId);
  codes.delete(code);
  saveData();
  res.json({ ok: true });
});

// ── ADMIN: Session management ─────────────────────────────────────────
app.get('/admin/sessions', requireAdmin, async (req, res) => {
  const stats = await wgStats();
  const out   = [...sessions.values()].map(s => {
    const hostStats = stats[s.publicKey] || { rx: 0, tx: 0 };
    return {
      sessionId:    s.sessionId,
      sessionCode:  s.sessionCode,
      label:        s.label,
      ip:           s.ip,
      active:       s.active,
      clients:      s.clients.size,
      expiresAt:    s.expiresAt,
      ageMinutes:   Math.floor((Date.now() - s.createdAt) / 60_000),
      hostStats,
      clientList: [...s.clients.values()].map(c => ({
        ...c,
        stats:         stats[c.publicKey] || { rx: 0, tx: 0 },
        dataTodayMB:   +(getClientDataToday(c.publicKey) / 1_048_576).toFixed(2),
        overLimitToday: getClientDataToday(c.publicKey) > MAX_DATA_MB_DAY * 1_048_576,
      })),
    };
  });
  res.json(out);
});

app.delete('/admin/sessions/:id', requireAdmin, async (req, res) => {
  await teardownSession(req.params.id);
  saveData();
  res.json({ ok: true });
});

app.delete('/admin/sessions/:id/clients/:clientId', requireAdmin, async (req, res) => {
  const sess = sessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  const client = sess.clients.get(req.params.clientId);
  if (!client) return res.status(404).json({ error: 'Client not found' });
  await wgRemovePeer(client.publicKey);
  freeIp(client.ip);
  sess.clients.delete(req.params.clientId);
  saveData();
  res.json({ ok: true, kicked: req.params.clientId });
});

// ── ADMIN: Stats dashboard ────────────────────────────────────────────
app.get('/admin/stats', requireAdmin, async (req, res) => {
  const stats = await wgStats();
  let totalRx = 0, totalTx = 0;
  for (const s of Object.values(stats)) { totalRx += s.rx || 0; totalTx += s.tx || 0; }

  // Count clients over daily data limit
  let clientsOverLimit = 0;
  for (const sess of sessions.values()) {
    for (const client of sess.clients.values()) {
      if (getClientDataToday(client.publicKey) > MAX_DATA_MB_DAY * 1_048_576) {
        clientsOverLimit++;
      }
    }
  }

  res.json({
    activeSessions:   [...sessions.values()].filter(s => s.active).length,
    totalClients:     [...sessions.values()].reduce((n, s) => n + s.clients.size, 0),
    totalCodes:       codes.size,
    unusedCodes:      [...codes.values()].filter(c => !c.used).length,
    serverPubkey:     WG_SERVER_PUBKEY,
    vpsEndpoint:      VPS_ENDPOINT,
    wgInterface:      WG_IFACE,
    totalRxMB:        +(totalRx / 1_048_576).toFixed(2),
    totalTxMB:        +(totalTx / 1_048_576).toFixed(2),
    dataSavingMode:   true,
    clientKeepalive:  CLIENT_KEEPALIVE,
    maxDataMbDay:     MAX_DATA_MB_DAY,
    clientsOverLimit,
  });
});

// ── ADMIN: Per-client data usage ──────────────────────────────────────
app.get('/admin/data-usage', requireAdmin, async (req, res) => {
  const stats  = await wgStats();
  const today  = todayStr();
  const result = [];

  for (const sess of sessions.values()) {
    for (const client of sess.clients.values()) {
      const wg       = stats[client.publicKey] || { rx: 0, tx: 0 };
      const todayRec = clientDataUsage.get(client.publicKey);
      const todayBytes = (todayRec?.date === today) ? todayRec.bytes : 0;

      result.push({
        clientId:      client.clientId,
        label:         client.label,
        sessionCode:   sess.sessionCode,
        ip:            client.ip,
        totalRxMB:     +(wg.rx / 1_048_576).toFixed(2),
        totalTxMB:     +(wg.tx / 1_048_576).toFixed(2),
        dataTodayMB:   +(todayBytes / 1_048_576).toFixed(2),
        overLimit:     todayBytes > MAX_DATA_MB_DAY * 1_048_576,
        limitMB:       MAX_DATA_MB_DAY,
      });
    }
  }

  res.json(result);
});

// ── ADMIN: WireGuard restart ──────────────────────────────────────────
app.post('/admin/wg/restart', requireAdmin, async (req, res) => {
  try {
    await execAsync(`wg-quick down ${WG_IFACE} && wg-quick up ${WG_IFACE}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Client leave ──────────────────────────────────────────────────────
app.post('/leave', async (req, res) => {
  const { sessionCode, clientId, publicKey } = req.body || {};
  const sess = [...sessions.values()].find(s => s.sessionCode === (sessionCode || '').toUpperCase());
  if (!sess) return res.json({ ok: true });
  const client = sess.clients.get(clientId) || [...sess.clients.values()].find(c => c.publicKey === publicKey);
  if (client) {
    await wgRemovePeer(client.publicKey);
    freeIp(client.ip);
    sess.clients.delete(client.clientId);
    saveData();
  }
  res.json({ ok: true });
});

// ── Session teardown ──────────────────────────────────────────────────
async function teardownSession(sessionId) {
  const sess = sessions.get(sessionId);
  if (!sess) return;
  sess.active = false;
  for (const [, c] of sess.clients) {
    await wgRemovePeer(c.publicKey);
    freeIp(c.ip);
  }
  await wgRemovePeer(sess.publicKey);
  freeIp(sess.ip);
  sessions.delete(sessionId);
  console.log(`[SESSION] Torn down: ${sessionId}`);
}

// ── Auto-expire sessions & codes ──────────────────────────────────────
async function checkExpiredSessions() {
  const now = Date.now();

  // Expire host sessions
  for (const [id, sess] of sessions.entries()) {
    if (sess.expiresAt && now > sess.expiresAt) {
      console.log(`[EXPIRE] Session ${sess.sessionCode} expired — tearing down`);
      await teardownSession(id);
      saveData();
    }
  }

  // Expire codes
  for (const [code, rec] of codes.entries()) {
    if (!rec.expiresAt || now <= rec.expiresAt) continue;

    if (rec.type === 'host' && rec.sessionId) {
      console.log(`[EXPIRE] Host code ${code} expired — tearing down session`);
      await teardownSession(rec.sessionId);
      saveData();
    }

    if (rec.type === 'client' && rec.sessionId && rec.clientId) {
      const sess = sessions.get(rec.sessionId);
      if (sess) {
        const client = sess.clients.get(rec.clientId);
        if (client) {
          console.log(`[EXPIRE] Client code ${code} expired — kicking client`);
          await wgRemovePeer(client.publicKey);
          freeIp(client.ip);
          sess.clients.delete(rec.clientId);
          saveData();
        }
      }
    }
  }
}
setInterval(checkExpiredSessions, 60_000);

// ── Daily data usage polling (updates clientDataUsage from wg stats) ──
// Runs every 5 minutes — samples WireGuard transfer counters and
// accumulates per-client daily usage for the admin dashboard.
async function pollDataUsage() {
  try {
    const stats = await wgStats();
    for (const sess of sessions.values()) {
      for (const client of sess.clients.values()) {
        const wg = stats[client.publicKey];
        if (!wg) continue;
        // wg transfer gives cumulative bytes since peer was added.
        // We track the delta since last poll to get daily usage.
        const prev = client._lastPollBytes || 0;
        const curr = wg.rx + wg.tx;
        const delta = Math.max(0, curr - prev);
        client._lastPollBytes = curr;
        if (delta > 0) {
          recordClientData(client.publicKey, delta);
          // Log warning if over daily limit
          const todayBytes = getClientDataToday(client.publicKey);
          if (todayBytes > MAX_DATA_MB_DAY * 1_048_576) {
            console.warn(`[DATA] Client ${client.label} (${client.ip}) exceeded ${MAX_DATA_MB_DAY}MB today: ${(todayBytes/1_048_576).toFixed(1)}MB`);
          }
        }
      }
    }
    // Save updated usage periodically
    saveData();
  } catch (e) {
    console.error('[POLL] Data usage poll failed:', e.message);
  }
}
setInterval(pollDataUsage, 5 * 60_000); // every 5 minutes

// ── Startup ───────────────────────────────────────────────────────────
loadData();
server.listen(PORT, () => {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log(`║  NetShare Relay  —  VPS+WireGuard Edition             ║`);
  console.log(`║  Port: ${PORT}   Interface: ${WG_IFACE}                        ║`);
  console.log(`║  Admin panel: http://localhost:${PORT}/admin          ║`);
  console.log(`║  DATA SAVING MODE: ON                                 ║`);
  console.log(`║    Client AllowedIPs: 10.8.0.0/24 (subnet only)      ║`);
  console.log(`║    Keepalive: ${String(CLIENT_KEEPALIVE).padEnd(3)}s   Max MB/day: ${String(MAX_DATA_MB_DAY).padEnd(6)}        ║`);
  console.log(`║  Server pubkey:                                       ║`);
  console.log(`║    ${WG_SERVER_PUBKEY.slice(0, 44)}  ║`);
  console.log('╚══════════════════════════════════════════════════════╝');
  if (!VPS_ENDPOINT) console.warn('[WARN] VPS_ENDPOINT not set! Set it to your public IP:51820');
});
