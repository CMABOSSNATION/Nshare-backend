/**
 * store/index.js — WireGuard VPN state (Redux Toolkit)
 * ══════════════════════════════════════════════════════
 *
 * State shape:
 * {
 *   vpn: {
 *     status:       'idle'|'connecting'|'connected'|'disconnecting'|'error'
 *     role:         'host'|'client'|null
 *     sessionCode:  string|null
 *     clientIp:     string|null
 *     serverEndpoint: string|null
 *     appPackages:  string[]
 *     connectedAt:  number|null   (timestamp)
 *     errorMsg:     string|null
 *     clients:      ClientInfo[]  (host only)
 *     bandwidth: {
 *       bytesSent:     number
 *       bytesReceived: number
 *       formattedUp:   string
 *       formattedDown: string
 *     }
 *   }
 * }
 */

import { configureStore, createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import * as WG from '../services/WireGuardService';
import { NativeEventEmitter, NativeModules } from 'react-native';

const { VpnModule } = NativeModules;

// ── Async thunks ──────────────────────────────────────────────────────

/** HOST: create a new sharing session */
export const hostStart = createAsyncThunk(
  'vpn/hostStart',
  async ({ appPackages, hostId }, { rejectWithValue }) => {
    try {
      const sessionData = await WG.hostRegister({ appPackages, hostId });
      await WG.startVpn(sessionData, 'host');
      return sessionData;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

/** CLIENT: join an existing session */
export const clientJoin = createAsyncThunk(
  'vpn/clientJoin',
  async ({ sessionCode, appPackages, deviceId }, { rejectWithValue }) => {
    try {
      // Validate code first (cheap round-trip)
      const check = await WG.validateSessionCode(sessionCode);
      if (!check.valid) return rejectWithValue(check.reason || 'Invalid session code');

      const sessionData = await WG.clientJoin({ sessionCode, appPackages, deviceId });
      await WG.startVpn(sessionData, 'client');
      return sessionData;
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

/** Both roles: disconnect */
export const disconnect = createAsyncThunk(
  'vpn/disconnect',
  async (_, { getState, rejectWithValue }) => {
    const { sessionCode, role } = getState().vpn;
    try {
      WG.closeEventSocket();
      await WG.stopVpn({ sessionCode, role });
    } catch (err) {
      return rejectWithValue(err.message);
    }
  }
);

/** Poll bandwidth from native layer */
export const refreshBandwidth = createAsyncThunk(
  'vpn/refreshBandwidth',
  async () => WG.getBandwidthStats()
);

// ── Slice ─────────────────────────────────────────────────────────────

const vpnSlice = createSlice({
  name: 'vpn',
  initialState: {
    status:         'idle',
    role:           null,
    sessionCode:    null,
    clientIp:       null,
    serverEndpoint: null,
    appPackages:    [],
    connectedAt:    null,
    errorMsg:       null,
    clients:        [],      // [{ deviceId, connectedAt }]
    bandwidth: {
      bytesSent:     0,
      bytesReceived: 0,
      formattedUp:   '0 B',
      formattedDown: '0 B',
    },
  },

  reducers: {
    // Native events push into store via these actions
    vpnConnected(state) {
      state.status      = 'connected';
      state.connectedAt = Date.now();
      state.errorMsg    = null;
    },
    vpnDisconnected(state) {
      state.status      = 'idle';
      state.connectedAt = null;
      state.clients     = [];
    },
    vpnError(state, action) {
      state.status   = 'error';
      state.errorMsg = action.payload;
    },
    clientConnected(state, action) {
      const { deviceId } = action.payload;
      if (!state.clients.find(c => c.deviceId === deviceId)) {
        state.clients.push({ deviceId, connectedAt: Date.now() });
      }
    },
    clientDisconnected(state, action) {
      state.clients = state.clients.filter(c => c.deviceId !== action.payload.deviceId);
    },
    bandwidthUpdated(state, action) {
      state.bandwidth = action.payload;
    },
  },

  extraReducers: builder => {
    // ── hostStart ─────────────────────────────────────────────────
    builder
      .addCase(hostStart.pending, state => {
        state.status   = 'connecting';
        state.errorMsg = null;
      })
      .addCase(hostStart.fulfilled, (state, action) => {
        // status will flip to 'connected' via vpnConnected event
        state.role           = 'host';
        state.sessionCode    = action.payload.sessionCode;
        state.clientIp       = action.payload.clientIp;
        state.serverEndpoint = action.payload.serverEndpoint;
        state.appPackages    = action.payload.appPackages || [];
      })
      .addCase(hostStart.rejected, (state, action) => {
        state.status   = 'error';
        state.errorMsg = action.payload;
      });

    // ── clientJoin ────────────────────────────────────────────────
    builder
      .addCase(clientJoin.pending, state => {
        state.status   = 'connecting';
        state.errorMsg = null;
      })
      .addCase(clientJoin.fulfilled, (state, action) => {
        state.role           = 'client';
        state.sessionCode    = action.payload.sessionCode;
        state.clientIp       = action.payload.clientIp;
        state.serverEndpoint = action.payload.serverEndpoint;
        state.appPackages    = action.payload.appPackages || [];
      })
      .addCase(clientJoin.rejected, (state, action) => {
        state.status   = 'error';
        state.errorMsg = action.payload;
      });

    // ── disconnect ────────────────────────────────────────────────
    builder
      .addCase(disconnect.pending, state => {
        state.status = 'disconnecting';
      })
      .addCase(disconnect.fulfilled, state => {
        state.status         = 'idle';
        state.role           = null;
        state.sessionCode    = null;
        state.clientIp       = null;
        state.serverEndpoint = null;
        state.appPackages    = [];
        state.connectedAt    = null;
        state.clients        = [];
        state.bandwidth      = { bytesSent: 0, bytesReceived: 0, formattedUp: '0 B', formattedDown: '0 B' };
      })
      .addCase(disconnect.rejected, state => {
        // Force idle even on error
        state.status = 'idle';
      });

    // ── refreshBandwidth ──────────────────────────────────────────
    builder.addCase(refreshBandwidth.fulfilled, (state, action) => {
      state.bandwidth = action.payload;
    });
  },
});

export const {
  vpnConnected,
  vpnDisconnected,
  vpnError,
  clientConnected,
  clientDisconnected,
  bandwidthUpdated,
} = vpnSlice.actions;

// ── Store ─────────────────────────────────────────────────────────────

export const store = configureStore({
  reducer: { vpn: vpnSlice.reducer },
});

// ── Native event → Redux bridge ───────────────────────────────────────
// Wire up native VPN events to Redux actions once at startup.

const emitter = new NativeEventEmitter(VpnModule);

emitter.addListener('vpnConnected',    ()       => store.dispatch(vpnConnected()));
emitter.addListener('vpnDisconnected', ()       => store.dispatch(vpnDisconnected()));
emitter.addListener('vpnError',        ({ data })=> store.dispatch(vpnError(data)));

// ── Bandwidth polling ─────────────────────────────────────────────────
// Poll every 3 seconds while connected — suspended when idle.

let _bandwidthPoll = null;

store.subscribe(() => {
  const { status } = store.getState().vpn;
  const polling = _bandwidthPoll !== null;

  if (status === 'connected' && !polling) {
    _bandwidthPoll = setInterval(() => {
      store.dispatch(refreshBandwidth());
    }, 3000);
  } else if (status !== 'connected' && polling) {
    clearInterval(_bandwidthPoll);
    _bandwidthPoll = null;
  }
});

// ── Relay WebSocket event → Redux bridge ──────────────────────────────
// Start the WebSocket for the host when a session is active.

let _lastCode = null;
store.subscribe(() => {
  const { sessionCode, role, status } = store.getState().vpn;

  if (status === 'connecting' && role === 'host' && sessionCode && sessionCode !== _lastCode) {
    _lastCode = sessionCode;
    WG.openEventSocket(sessionCode, 'host', (msg) => {
      if (msg.type === 'clientConnected')    store.dispatch(clientConnected(msg));
      if (msg.type === 'clientDisconnected') store.dispatch(clientDisconnected(msg));
      if (msg.type === 'hostLeft')           store.dispatch(vpnDisconnected());
    });
  }

  if (status === 'idle') {
    _lastCode = null;
    WG.closeEventSocket();
  }
});

export default store;
