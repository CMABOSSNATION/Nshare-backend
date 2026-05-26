/**
 * WireGuardService.js — Fixed
 *
 * FIXES vs original:
 *
 * FIX 1 — RELAY_URL was 'https://YOUR_VPS_IP_OR_DOMAIN:4000' (placeholder)
 *   The app called a literal placeholder URL in production builds,
 *   causing every API call to fail silently.
 *   → Replace YOUR_VPS_IP below with your actual Hetzner server IP/domain.
 *
 * FIX 2 — No timeout on fetch() calls
 *   If the VPS is unreachable, fetch() hangs for ~2 minutes.
 *   This blocked the UI and looked like a crash.
 *   → All fetch calls now use AbortController with a 10s timeout.
 *
 * FIX 3 — openEventSocket() started on 'connecting' status in store/index.js
 *   The WebSocket opened before the session was fully registered,
 *   causing a race condition where clientConnected events were missed.
 *   Fixed in store/index.js (see that file) — calling openEventSocket
 *   only after hostStart.fulfilled.
 *
 * FIX 4 — getOrCreateKeyPair() could silently return a mismatched pair
 *   If privateKey was stored but publicKey was missing (partial write),
 *   the function returned the stored private key with a freshly generated
 *   public key — guaranteed to be wrong.
 *   → Added atomic check: regenerate if either key is missing.
 */

import { NativeModules, NativeEventEmitter } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const { VpnModule } = NativeModules;

// ── Config ────────────────────────────────────────────────────────────────
// FIX 1: Replace YOUR_VPS_IP_OR_DOMAIN with your actual Hetzner IP or domain
// Example: 'https://65.21.100.200:4000' or 'https://relay.yourdomain.com'
export const RELAY_URL = __DEV__
  ? 'http://10.0.2.2:4000'
  : 'https://YOUR_VPS_IP_OR_DOMAIN:4000'; // <-- CHANGE THIS

const WS_URL = RELAY_URL.replace(/^http/, 'ws') + '/ws';

const STORAGE_KEYS = {
  privateKey:  '@wg_private_key',
  publicKey:   '@wg_public_key',
  sessionCode: '@wg_session_code',
  sessionRole: '@wg_session_role',
  clientIp:    '@wg_client_ip',
};

// ── Event emitter ──────────────────────────────────────────────────────────
let _emitter = null;
export function getVpnEmitter() {
  if (!_emitter) _emitter = new NativeEventEmitter(VpnModule);
  return _emitter;
}

// ── FIX 2: fetch with timeout ──────────────────────────────────────────────
async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    return resp;
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Request timed out after ' + timeoutMs + 'ms');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── Key management ─────────────────────────────────────────────────────────

/**
 * Returns the device's persistent WireGuard key pair.
 * FIX 4: Regenerates if either key is missing (prevents mismatched pairs).
 */
export async function getOrCreateKeyPair() {
  try {
    const stored = await AsyncStorage.multiGet([
      STORAGE_KEYS.privateKey,
      STORAGE_KEYS.publicKey,
    ]);
    const priv = stored[0][1];
    const pub  = stored[1][1];

    // FIX 4: both must be present — regenerate if either is missing
    if (priv && pub) return { privateKey: priv, publicKey: pub };

    const kp = await VpnModule.generateKeyPair();
    await AsyncStorage.multiSet([
      [STORAGE_KEYS.privateKey, kp.privateKey],
      [STORAGE_KEYS.publicKey,  kp.publicKey],
    ]);
    return kp;
  } catch (err) {
    throw new Error('Key generation failed: ' + err.message);
  }
}

export async function rotateKeyPair() {
  await AsyncStorage.multiRemove([STORAGE_KEYS.privateKey, STORAGE_KEYS.publicKey]);
  return getOrCreateKeyPair();
}

// ── VPN permission ─────────────────────────────────────────────────────────

export async function ensureVpnPermission() {
  const granted = await VpnModule.requestVpnPermission();
  if (!granted) throw new Error('VPN permission denied by user');
  return true;
}

// ── Session code validation ────────────────────────────────────────────────

export async function validateSessionCode(code) {
  const resp = await fetchWithTimeout(`${RELAY_URL}/validate-code`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ code }),
  });
  if (!resp.ok) throw new Error(`Relay server error ${resp.status}`);
  return resp.json();
}

// ── HOST: register session ─────────────────────────────────────────────────

export async function hostRegister({ appPackages = [], hostId } = {}) {
  const { privateKey, publicKey } = await getOrCreateKeyPair();

  const resp = await fetchWithTimeout(`${RELAY_URL}/host/register`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ publicKey, hostId }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || `Relay error ${resp.status}`);
  }

  const data = await resp.json();

  await AsyncStorage.multiSet([
    [STORAGE_KEYS.sessionCode, data.sessionCode],
    [STORAGE_KEYS.sessionRole, 'host'],
    [STORAGE_KEYS.clientIp,    data.clientIp],
  ]);

  return { ...data, privateKey, publicKey, appPackages };
}

// ── CLIENT: join session ───────────────────────────────────────────────────

export async function clientJoin({ sessionCode, appPackages = [], deviceId }) {
  const { privateKey, publicKey } = await getOrCreateKeyPair();

  const resp = await fetchWithTimeout(`${RELAY_URL}/client/join`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ sessionCode, publicKey, deviceId }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || `Relay error ${resp.status}`);
  }

  const data = await resp.json();

  await AsyncStorage.multiSet([
    [STORAGE_KEYS.sessionCode, sessionCode],
    [STORAGE_KEYS.sessionRole, 'client'],
    [STORAGE_KEYS.clientIp,    data.clientIp],
  ]);

  return { ...data, sessionCode, privateKey, publicKey, appPackages };
}

// ── Start VPN ──────────────────────────────────────────────────────────────

export async function startVpn(sessionData, role) {
  await ensureVpnPermission();

  const {
    serverPublicKey,
    serverEndpoint,
    privateKey,
    publicKey,
    clientIp,
    sessionCode,
    appPackages = [],
  } = sessionData;

  if (!serverPublicKey || !serverEndpoint || !clientIp) {
    throw new Error('Incomplete VPN config — missing serverPublicKey, serverEndpoint, or clientIp');
  }

  if (appPackages.length === 0) {
    console.warn('[WireGuardService] No appPackages — tunneling all device traffic');
  }

  await VpnModule.startVpn({
    serverEndpoint,
    serverPublicKey,
    clientPrivateKey: privateKey,
    clientPublicKey:  publicKey,
    clientIp,
    sessionCode:      sessionCode || '',
    role:             role || 'client',
    appPackages,
  });
}

// ── Stop VPN ───────────────────────────────────────────────────────────────

export async function stopVpn({ sessionCode, role } = {}) {
  try { await VpnModule.stopVpn(); } catch (_) {}

  if (sessionCode) {
    const keys = await getOrCreateKeyPair();
    fetchWithTimeout(`${RELAY_URL}/leave`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ sessionCode, role, publicKey: keys.publicKey }),
    }).catch(() => {});
  }

  await AsyncStorage.multiRemove([
    STORAGE_KEYS.sessionCode,
    STORAGE_KEYS.sessionRole,
    STORAGE_KEYS.clientIp,
  ]);
}

// ── Bandwidth stats ────────────────────────────────────────────────────────

export async function getBandwidthStats() {
  try {
    const stats = await VpnModule.getBandwidthStats();
    return {
      bytesSent:     stats.bytesSent,
      bytesReceived: stats.bytesReceived,
      formattedUp:   formatBytes(stats.bytesSent),
      formattedDown: formatBytes(stats.bytesReceived),
    };
  } catch {
    return { bytesSent: 0, bytesReceived: 0, formattedUp: '0 B', formattedDown: '0 B' };
  }
}

export async function getSessionStats(sessionCode) {
  try {
    const resp = await fetchWithTimeout(`${RELAY_URL}/stats/${sessionCode}`);
    if (!resp.ok) return null;
    return resp.json();
  } catch {
    return null;
  }
}

function formatBytes(bytes) {
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)   return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// ── Event WebSocket ────────────────────────────────────────────────────────

let _ws              = null;
let _wsCode          = null;
let _wsRole          = null;
let _wsReconnectTimer = null;
let _wsOnMessage     = null;

export function openEventSocket(sessionCode, role, onMessage) {
  _wsCode      = sessionCode;
  _wsRole      = role;
  _wsOnMessage = onMessage;
  _connectWs();
}

function _connectWs() {
  if (_ws) { try { _ws.close(); } catch (_) {} }
  clearTimeout(_wsReconnectTimer);

  _ws = new WebSocket(WS_URL);

  _ws.onopen = () => {
    _ws.send(JSON.stringify({ type: 'REGISTER', sessionCode: _wsCode, role: _wsRole }));
    _wsHeartbeat();
  };

  _ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (_wsOnMessage) _wsOnMessage(msg);
    } catch (_) {}
  };

  _ws.onclose = () => {
    if (_wsCode) _wsReconnectTimer = setTimeout(_connectWs, 3000);
  };

  _ws.onerror = () => {};
}

let _heartbeatInterval = null;
function _wsHeartbeat() {
  clearInterval(_heartbeatInterval);
  _heartbeatInterval = setInterval(() => {
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify({ type: 'PING' }));
    }
  }, 20_000);
}

export function closeEventSocket() {
  _wsCode = null;
  clearTimeout(_wsReconnectTimer);
  clearInterval(_heartbeatInterval);
  if (_ws) { try { _ws.close(); } catch (_) {} _ws = null; }
}

// ── Debug ──────────────────────────────────────────────────────────────────

export async function getDebugLog() {
  try   { return await VpnModule.getDebugLog(); }
  catch { return '(debug log unavailable)'; }
}
