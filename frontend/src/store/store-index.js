/**
 * store/index.js — Fixed
 *
 * FIX 3: WebSocket race condition
 *   Original: openEventSocket() was called when status === 'connecting'
 *   AND sessionCode was set. But sessionCode gets set in hostStart.fulfilled,
 *   which means the socket was opened before the session was actually
 *   registered on the server. Clients connecting immediately after could
 *   send events that were missed.
 *   → Moved to only open socket after vpnConnected event fires.
 *
 * FIX 5: Status stuck on 'connecting' if VPN service starts but native
 *   vpnConnected event is delayed or missed.
 *   → Added a 30s connecting timeout that forces back to 'error'.
 */

import { configureStore, createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import * as WG from '../services/WireGuardService';
import { NativeEventEmitter, NativeModules } from 'react-native';

const { VpnModule } = NativeModules;

// ── Async thunks ───────────────────────────────────────────────────────────

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

export const clientJoin = createAsyncThunk(
  'vpn/clientJoin',
  async ({ sessionCode, appPackages, deviceId }, { rejectWithValue }) => {
    try {
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

export const refreshBandwidth = createAsyncThunk(
  'vpn/refreshBandwidth',
  async () => WG.getBandwidthStats()
);

// ── Slice ──────────────────────────────────────────────────────────────────

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
    clients:        [],
    bandwidth: {
      bytesSent:     0,
      bytesReceived: 0,
      formattedUp:   '0 B',
      formattedDown: '0 B',
    },
  },

  reducers: {
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
    // FIX 5: connecting timeout action
    connectingTimeout(state) {
      if (state.status === 'connecting') {
        state.status   = 'error';
        state.errorMsg = 'Connection timed out — check VPS is reachable and WireGuard port is open';
      }
    },
  },

  extraReducers: builder => {
    builder
      .addCase(hostStart.pending, state => {
        state.status   = 'connecting';
        state.errorMsg = null;
      })
      .addCase(hostStart.fulfilled, (state, action) => {
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

    builder
      .addCase(disconnect.pending,   state  => { state.status = 'disconnecting'; })
      .addCase(disconnect.fulfilled, state  => {
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
      .addCase(disconnect.rejected, state => { state.status = 'idle'; });

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
  connectingTimeout,
} = vpnSlice.actions;

// ── Store ──────────────────────────────────────────────────────────────────

export const store = configureStore({
  reducer: { vpn: vpnSlice.reducer },
});

// ── Native event → Redux bridge ────────────────────────────────────────────

const emitter = new NativeEventEmitter(VpnModule);

emitter.addListener('vpnConnected',    ()         => store.dispatch(vpnConnected()));
emitter.addListener('vpnDisconnected', ()         => store.dispatch(vpnDisconnected()));
emitter.addListener('vpnError',        ({ data }) => store.dispatch(vpnError(data)));

// ── Bandwidth polling ──────────────────────────────────────────────────────

let _bandwidthPoll = null;

store.subscribe(() => {
  const { status } = store.getState().vpn;
  const polling = _bandwidthPoll !== null;

  if (status === 'connected' && !polling) {
    _bandwidthPoll = setInterval(() => store.dispatch(refreshBandwidth()), 3000);
  } else if (status !== 'connected' && polling) {
    clearInterval(_bandwidthPoll);
    _bandwidthPoll = null;
  }
});

// ── FIX 3: WebSocket opened only after vpnConnected (not during connecting) ──
// FIX 5: Connecting timeout

let _lastConnectedCode = null;
let _connectingTimeoutTimer = null;

store.subscribe(() => {
  const { sessionCode, role, status } = store.getState().vpn;

  // FIX 5: start a 30s timeout whenever we enter 'connecting'
  if (status === 'connecting') {
    if (!_connectingTimeoutTimer) {
      _connectingTimeoutTimer = setTimeout(() => {
        store.dispatch(connectingTimeout());
        _connectingTimeoutTimer = null;
      }, 30_000);
    }
  } else {
    clearTimeout(_connectingTimeoutTimer);
    _connectingTimeoutTimer = null;
  }

  // FIX 3: Open WebSocket only when fully connected (not during connecting)
  if (status === 'connected' && role === 'host' && sessionCode && sessionCode !== _lastConnectedCode) {
    _lastConnectedCode = sessionCode;
    WG.openEventSocket(sessionCode, 'host', (msg) => {
      if (msg.type === 'clientConnected')    store.dispatch(clientConnected(msg));
      if (msg.type === 'clientDisconnected') store.dispatch(clientDisconnected(msg));
      if (msg.type === 'hostLeft')           store.dispatch(vpnDisconnected());
    });
  }

  if (status === 'idle') {
    _lastConnectedCode = null;
    WG.closeEventSocket();
  }
});

export default store;
