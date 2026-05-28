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
 *  Environment variables (set in /etc/environment or PM2 ecosystem):
 *    PORT          API port (default 4000)
 *    ADMIN_KEY     Admin panel password
 *    WG_IFACE      WireGuard interface (default wg0)
 *    VPS_ENDPOINT  Public IP:port of this VPS, e.g. 1.2.3.4:51820
 *    MAX_CLIENTS   Max clients per host session (default 10)
 *    DATA_FILE     Path to persist sessions/codes (default /opt/netshare-relay/data.json)
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
const PORT        = Number(process.env.PORT        || 4000);
const ADMIN_KEY   = process.env.ADMIN_KEY          || 'change-me-NOW';
const WG_IFACE    = process.env.WG_IFACE           || 'wg0';
const VPS_ENDPOINT= process.env.VPS_ENDPOINT       || ''; // REQUIRED: "1.2.3.4:51820"
const MAX_CLIENTS = Number(process.env.MAX_CLIENTS || 10);
const DATA_FILE   = process.env.DATA_FILE          || '/opt/netshare-relay/data.json';
const WG_CONF_PATH= `/etc/wireguard/${WG_IFACE}.conf`;

// ── State (persisted to DATA_FILE) ───────────────────────────────────
// codes:    Map<code, CodeRecord>
// sessions: Map<sessionId, SessionRecord>
// ipUsed:   Set<number>  (last octet of 10.8.0.X)

let codes    = new Map();  // access codes (host or client invite)
let sessions = new Map();  // active WireGuard sessions
let ipUsed   = new Set();  // allocated IPs

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
      ipUsed:   [...ipUsed],
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
  // Persist to wg0.conf so it survives reboots
  let conf = '';
  try { conf = readFileSync(WG_CONF_PATH, 'utf8'); } catch {}
  // Remove existing stanza for this key
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

// Generate a complete WireGuard .conf text for a peer
function buildWgConf({ peerPrivateKey, peerIp, dns = '1.1.1.1,8.8.8.8', allowedIPs = '0.0.0.0/0, ::/0' }) {
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
    'PersistentKeepalive = 25',
  ].join('\n');
}

// Generate a WireGuard keypair using the wg command
function genKeypair() {
  const priv = execSync('wg genkey').toString().trim();
  const pub  = execSync(`echo "${priv}" | wg pubkey`).toString().trim();
  return { priv, pub };
}

// ── Express app ───────────────────────────────────────────────────────
const app    = express();
const server = createServer(app);

app.use(cors());
app.use(express.json());

// Serve the admin panel static files
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// Serve the public download page at /download?code=XXXX-XXXX
app.get('/download', (_, res) => res.sendFile(path.join(__dirname, 'download.html')));
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'download.html')));

// ── Auth middleware ───────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (key !== ADMIN_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── Health ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({
  ok: true,
  sessions: sessions.size,
  codes: codes.size,
  vpsEndpoint: VPS_ENDPOINT,
  serverPubkey: WG_SERVER_PUBKEY,
}));

// ── Config download (public, requires valid code) ─────────────────────
/**
 * GET /config?code=XXXX-XXXX
 * Returns a WireGuard .conf file the user can import directly into the
 * official WireGuard app on any platform.
 *
 * The server generates the keypair on behalf of the user so they don't
 * need any command-line knowledge — just scan/tap and import.
 */
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

  // Generate peer keypair
  let keypair;
  try { keypair = genKeypair(); }
  catch (e) { return res.status(500).json({ error: 'Failed to generate WireGuard keys: ' + e.message }); }

  // Allocate IP
  let peerIp;
  try { peerIp = allocIp(); }
  catch (e) { return res.status(503).json({ error: e.message }); }

  // Add peer to WireGuard
  try { await wgAddPeer(keypair.pub, peerIp); }
  catch (e) {
    freeIp(peerIp);
    return res.status(500).json({ error: 'WireGuard peer setup failed: ' + e.message });
  }

  const sessionId = crypto.randomUUID();
  const now       = Date.now();

  if (codeRecord.type === 'host') {
    // HOST session — others join using this session's client codes
    const sessionCode = genCode();  // shareable code for clients to join
    sessions.set(sessionId, {
      sessionId,
      sessionCode,
      type:        'host',
      codeUsed:    code,
      publicKey:   keypair.pub,
      ip:          peerIp,
      label:       codeRecord.label || 'Host',
      clients:     new Map(),
      createdAt:   now,
      active:      true,
    });
    // Update code as used but keep it (host may reconnect)
    codeRecord.used      = true;
    codeRecord.sessionId = sessionId;
    codes.set(code, codeRecord);
    saveData();

    const conf = buildWgConf({ peerPrivateKey: keypair.priv, peerIp });
    const filename = `netshare-host-${sessionCode}.conf`;
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    // Append session info as comments at the top
    return res.send(
      `# NetShare HOST Config\n# Session Code (share with clients): ${sessionCode}\n# Generated: ${new Date().toISOString()}\n\n${conf}`
    );
  }

  if (codeRecord.type === 'client') {
    // CLIENT joining a host session
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
      clientId, publicKey: keypair.pub, ip: peerIp,
      label: codeRecord.label || 'Client', joinedAt: now,
    });
    codeRecord.used      = true;
    codeRecord.sessionId = hostSession.sessionId;
    codeRecord.clientId  = clientId;
    codes.set(code, codeRecord);
    saveData();

    const conf = buildWgConf({ peerPrivateKey: keypair.priv, peerIp });
    const filename = `netshare-client-${code}.conf`;
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(`# NetShare CLIENT Config\n# Code: ${code}\n# Generated: ${new Date().toISOString()}\n\n${conf}`);
  }

  return res.status(400).json({ error: 'Invalid code type' });
});

/**
 * GET /config/info?code=XXXX-XXXX
 * Returns info about the code (type, valid, expiry) — used by the
 * download page before actually downloading.
 */
app.get('/config/info', (req, res) => {
  const code = cleanCode(req.query.code);
  const rec  = codes.get(code);
  if (!rec) return res.status(404).json({ valid: false, reason: 'Invalid code' });
  if (rec.expiresAt && Date.now() > rec.expiresAt) return res.json({ valid: false, reason: 'Code expired' });
  if (rec.used && rec.type !== 'host') return res.json({ valid: false, reason: 'Code already used' });
  res.json({
    valid: true,
    type: rec.type,
    label: rec.label,
    sessionCode: rec.sessionCode,
  });
});

// ── ADMIN: Code management ────────────────────────────────────────────

/** POST /admin/codes/create
 *  Body: { type: "host"|"client", label, sessionCode, count, expiresInHours }
 *  - type "host": creates a code that lets someone become a host
 *  - type "client": creates one or more codes that let someone join
 *    a specific host session (sessionCode required)
 */
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

/** GET /admin/codes  — list all codes */
app.get('/admin/codes', requireAdmin, (req, res) => {
  const out = [...codes.values()].map(c => ({
    ...c,
    expired: c.expiresAt ? Date.now() > c.expiresAt : false,
  }));
  res.json(out);
});

/** DELETE /admin/codes/:code */
app.delete('/admin/codes/:code', requireAdmin, async (req, res) => {
  const code = cleanCode(req.params.code);
  const rec  = codes.get(code);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  // If a session exists for this code, tear it down
  if (rec.sessionId) {
    await teardownSession(rec.sessionId);
  }
  codes.delete(code);
  saveData();
  res.json({ ok: true });
});

// ── ADMIN: Session management ─────────────────────────────────────────

/** GET /admin/sessions */
app.get('/admin/sessions', requireAdmin, async (req, res) => {
  const stats = await wgStats();
  const out   = [...sessions.values()].map(s => {
    const hostStats = stats[s.publicKey] || { rx: 0, tx: 0 };
    return {
      sessionId:   s.sessionId,
      sessionCode: s.sessionCode,
      label:       s.label,
      ip:          s.ip,
      active:      s.active,
      clients:     s.clients.size,
      clientList:  [...s.clients.values()].map(c => ({ ...c, stats: stats[c.publicKey] || { rx: 0, tx: 0 } })),
      hostStats,
      ageMinutes:  Math.floor((Date.now() - s.createdAt) / 60_000),
    };
  });
  res.json(out);
});

/** DELETE /admin/sessions/:sessionId */
app.delete('/admin/sessions/:id', requireAdmin, async (req, res) => {
  await teardownSession(req.params.id);
  saveData();
  res.json({ ok: true });
});

/** DELETE /admin/sessions/:id/clients/:clientId — kick one client */
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

/** GET /admin/stats — summary dashboard numbers */
app.get('/admin/stats', requireAdmin, async (req, res) => {
  const stats = await wgStats();
  let totalRx = 0, totalTx = 0;
  for (const s of stats) { totalRx += s.rx || 0; totalTx += s.tx || 0; }
  res.json({
    activeSessions: [...sessions.values()].filter(s => s.active).length,
    totalClients:   [...sessions.values()].reduce((n, s) => n + s.clients.size, 0),
    totalCodes:     codes.size,
    unusedCodes:    [...codes.values()].filter(c => !c.used).length,
    serverPubkey:   WG_SERVER_PUBKEY,
    vpsEndpoint:    VPS_ENDPOINT,
    wgInterface:    WG_IFACE,
  });
});

/** POST /admin/wg/restart — restarts the wg interface */
app.post('/admin/wg/restart', requireAdmin, async (req, res) => {
  try {
    await execAsync(`wg-quick down ${WG_IFACE} && wg-quick up ${WG_IFACE}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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

// ── Startup ───────────────────────────────────────────────────────────
loadData();
server.listen(PORT, () => {
  console.log('╔══════════════════════════════════════════════╗');
  console.log(`║  NetShare Relay  —  VPS+WireGuard Edition    ║`);
  console.log(`║  Port: ${PORT}   Interface: ${WG_IFACE}              ║`);
  console.log(`║  Admin panel: http://localhost:${PORT}/admin  ║`);
  console.log(`║  Server pubkey:                              ║`);
  console.log(`║    ${WG_SERVER_PUBKEY.slice(0, 44)}  ║`);
  console.log('╚══════════════════════════════════════════════╝');
  if (!VPS_ENDPOINT) console.warn('[WARN] VPS_ENDPOINT not set! Set it to your public IP:51820');
});
