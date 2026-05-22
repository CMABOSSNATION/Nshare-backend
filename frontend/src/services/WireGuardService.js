/**
 * WireGuardService.js
 * ═══════════════════
 * All WireGuard + VPS relay API calls.
 * Replaces the old CloudflareService.js / TikTok.js pattern.
 *
 * Responsibilities:
 *   • Key pair generation (via native VpnModule)
 *   • Host session registration with VPS relay
 *   • Client session join
 *   • VPN start / stop (via native VpnModule)
 *   • Live bandwidth polling (REST + native)
 *   • WebSocket keep-alive for host presence signal
 *   • Session code validation
 *
 * Split-tunnel guarantee:
 *   startVpn() always passes appPackages from config.
 *   If no packages are specified the VPN still starts but
 *   only the calling app's own package is excluded —
 *   this is logged as a warning.
 */

import { NativeModules, NativeEventEmitter } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const { VpnModule } = NativeModules;

// ── Config ───────────────────────────────────────────────────────────
// Change RELAY_URL to your VPS IP / domain.
export const RELAY_URL = __DEV__
  ? 'http://10.0.2.2:4000'           // Android emulator → host loopback
  : 'https://YOUR_VPS_IP_OR_DOMAIN:4000';

const WS_URL = RELAY_URL.replace(/^http/, 'ws') + '/ws';

const STORAGE_KEYS = {
  privateKey:  '@wg_private_key',
  publicKey:   '@wg_public_key',
  sessionCode: '@wg_session_code',
  sessionRole: '@wg_session_role',
  clientIp:    '@wg_client_ip',
};

// ── Event emitter ────────────────────────────────────────────────────
let _emitter = null;
export function getVpnEmitter() {
  if (!_emitter) _emitter = new NativeEventEmitter(VpnModule);
  return _emitter;
}

// ── Key management ───────────────────────────────────────────────────

/**
 * Returns the device's persistent WireGuard key pair.
 * Generates and stores one on first call.
 */
export async function getOrCreateKeyPair() {
  try {
    const stored = await AsyncStorage.multiGet([
      STORAGE_KEYS.privateKey,
      STORAGE_KEYS.publicKey,
    ]);
    const priv = stored[0][1];
    const pub  = stored[1][1];
    if (priv && pub) return { privateKey: priv, publicKey: pub };

    // Generate fresh keypair
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

/** Force-regenerate keys (e.g. after security concern) */
export async function rotateKeyPair() {
  await AsyncStorage.multiRemove([STORAGE_KEYS.privateKey, STORAGE_KEYS.publicKey]);
  return getOrCreateKeyPair();
}

// ── VPN permission ───────────────────────────────────────────────────

export async function ensureVpnPermission() {
  const granted = await VpnModule.requestVpnPermission();
  if (!granted) throw new Error('VPN permission denied by user');
  return true;
}

// ── Session code validation ───────────────────────────────────────────

export async function validateSessionCode(code) {
  const resp = await fetch(`${RELAY_URL}/validate-code`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ code }),
  });
  if (!resp.ok) throw new Error('Relay server unreachable');
  return resp.json(); // { valid: bool, reason?: string }
}

// ── HOST: register session ────────────────────────────────────────────

/**
 * Called by the host device to create a sharing session.
 *
 * @param {object} opts
 *   appPackages: string[]   — packages to tunnel through VPN (split-tunnel)
 *   hostId:     string      — stable device ID
 *
 * @returns {object}
 *   sessionCode, serverPublicKey, serverEndpoint, clientIp
 */
export async function hostRegister({ appPackages = [], hostId } = {}) {
  const { privateKey, publicKey } = await getOrCreateKeyPair();

  const resp = await fetch(`${RELAY_URL}/host/register`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ publicKey, hostId }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || `Relay error ${resp.status}`);
  }

  const data = await resp.json();
  // { sessionCode, serverPublicKey, serverEndpoint, clientIp, dns }

  // Persist for reconnection
  await AsyncStorage.multiSet([
    [STORAGE_KEYS.sessionCode, data.sessionCode],
    [STORAGE_KEYS.sessionRole, 'host'],
    [STORAGE_KEYS.clientIp,    data.clientIp],
  ]);

  return {
    ...data,
    privateKey,
    publicKey,
    appPackages,
  };
}

// ── CLIENT: join session ──────────────────────────────────────────────

/**
 * Called by a client device to join an existing session.
 *
 * @param {object} opts
 *   sessionCode: string     — 8-char code from host
 *   appPackages: string[]   — apps to tunnel (split-tunnel)
 *   deviceId:   string      — stable device ID
 */
export async function clientJoin({ sessionCode, appPackages = [], deviceId }) {
  const { privateKey, publicKey } = await getOrCreateKeyPair();

  const resp = await fetch(`${RELAY_URL}/client/join`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ sessionCode, publicKey, deviceId }),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || `Relay error ${resp.status}`);
  }

  const data = await resp.json();
  // { serverPublicKey, serverEndpoint, clientIp, dns }

  await AsyncStorage.multiSet([
    [STORAGE_KEYS.sessionCode, sessionCode],
    [STORAGE_KEYS.sessionRole, 'client'],
    [STORAGE_KEYS.clientIp,    data.clientIp],
  ]);

  return {
    ...data,
    sessionCode,
    privateKey,
    publicKey,
    appPackages,
  };
}

// ── Start VPN tunnel ──────────────────────────────────────────────────

/**
 * Starts the WireGuard VPN service with split-tunnel config.
 *
 * appPackages controls which apps are routed through the tunnel.
 * Any app NOT in this list continues using the device's real
 * internet connection — this is how we prevent background
 * bandwidth consumption.
 *
 * @param {object} sessionData   — returned from hostRegister() or clientJoin()
 * @param {string} role          — 'host' | 'client'
 */
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
    console.warn('[WireGuardService] No appPackages specified — tunneling all device traffic');
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

// ── Stop VPN ──────────────────────────────────────────────────────────

export async function stopVpn({ sessionCode, role } = {}) {
  try { await VpnModule.stopVpn(); } catch {}

  // Notify relay server
  if (sessionCode) {
    const keys = await getOrCreateKeyPair();
    fetch(`${RELAY_URL}/leave`, {
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

// ── Bandwidth stats ───────────────────────────────────────────────────

/**
 * Returns { bytesSent, bytesReceived, formattedUp, formattedDown }
 * from the native WireGuard interface counters.
 */
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

/** Poll the VPS relay for per-session stats (includes per-client breakdown) */
export async function getSessionStats(sessionCode) {
  try {
    const resp = await fetch(`${RELAY_URL}/stats/${sessionCode}`);
    if (!resp.ok) return null;
    return resp.json();
    // { host: { rx, tx }, clients: { deviceId: { rx, tx } }, clientCount }
  } catch {
    return null;
  }
}

function formatBytes(bytes) {
  if (bytes < 1024)           return `${bytes} B`;
  if (bytes < 1024 * 1024)   return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)     return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

// ── Host presence WebSocket ───────────────────────────────────────────

let _ws = null;
let _wsCode = null;
let _wsRole = null;
let _wsReconnectTimer = null;
let _wsOnMessage = null;

/**
 * Opens a WebSocket to the relay server to receive real-time events.
 * Used by the host to get clientConnected / clientDisconnected events.
 *
 * @param {string}   sessionCode
 * @param {string}   role          'host' | 'client'
 * @param {function} onMessage     (msg: object) => void
 */
export function openEventSocket(sessionCode, role, onMessage) {
  _wsCode = sessionCode;
  _wsRole = role;
  _wsOnMessage = onMessage;
  _connectWs();
}

function _connectWs() {
  if (_ws) { try { _ws.close(); } catch {} }
  clearTimeout(_wsReconnectTimer);

  _ws = new WebSocket(WS_URL);

  _ws.onopen = () => {
    _ws.send(JSON.stringify({ type: 'REGISTER', sessionCode: _wsCode, role: _wsRole }));
    // Start heartbeat
    _wsHeartbeat();
  };

  _ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (_wsOnMessage) _wsOnMessage(msg);
    } catch {}
  };

  _ws.onclose = () => {
    // Reconnect after 3s backoff (unless manually closed)
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
  if (_ws) { try { _ws.close(); } catch {} _ws = null; }
}

// ── Debug ─────────────────────────────────────────────────────────────

export async function getDebugLog() {
  try { return await VpnModule.getDebugLog(); }
  catch { return '(debug log unavailable)'; }
}
