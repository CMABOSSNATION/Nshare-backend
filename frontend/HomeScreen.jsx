/**
 * HomeScreen.jsx — WireGuard Edition
 * ════════════════════════════════════
 *
 * Three views in one screen:
 *   IDLE       → role picker (Host / Join)
 *   CONNECTING → spinner
 *   CONNECTED  → live stats + disconnect
 *
 * Split-tunnel UX:
 *   Before starting, the user selects which apps to share.
 *   Only those app's traffic goes through the tunnel.
 *   We default to the most common apps (TikTok, YouTube, etc.)
 *   and let the user add/remove from the list.
 *   This is the UI enforcement of "doesn't consume client internet
 *   in the background" — background apps never enter the tunnel.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  ActivityIndicator, ScrollView, Switch, Alert,
  Clipboard, Share, Animated, Platform,
} from 'react-native';
import { useDispatch, useSelector } from 'react-redux';
import {
  hostStart, clientJoin, disconnect, refreshBandwidth,
} from '../store/index';

// ── Preset apps for split-tunnel selection ────────────────────────────
const PRESET_APPS = [
  { label: 'TikTok',     pkg: 'com.zhiliaoapp.musically' },
  { label: 'YouTube',    pkg: 'com.google.android.youtube' },
  { label: 'Instagram',  pkg: 'com.instagram.android' },
  { label: 'Snapchat',   pkg: 'com.snapchat.android' },
  { label: 'Twitter / X',pkg: 'com.twitter.android' },
  { label: 'Facebook',   pkg: 'com.facebook.katana' },
  { label: 'Netflix',    pkg: 'com.netflix.mediaclient' },
  { label: 'Spotify',    pkg: 'com.spotify.music' },
  { label: 'WhatsApp',   pkg: 'com.whatsapp' },
  { label: 'Chrome',     pkg: 'com.android.chrome' },
];

// ── Helpers ───────────────────────────────────────────────────────────
function formatDuration(ms) {
  if (!ms) return '0s';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0)  return `${h}h ${m % 60}m`;
  if (m > 0)  return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function DeviceId() {
  // Stable pseudo-ID — replace with react-native-device-info in production
  const ref = useRef(null);
  if (!ref.current) {
    ref.current = 'dev-' + Math.random().toString(36).slice(2, 10);
  }
  return ref.current;
}

// ── Main component ────────────────────────────────────────────────────

export default function HomeScreen() {
  const dispatch = useDispatch();
  const vpn      = useSelector(s => s.vpn);
  const deviceId = DeviceId();

  // Local UI state
  const [view,         setView]         = useState('idle');   // 'idle'|'roleSelect'|'appSelect'|'joinEntry'
  const [pendingRole,  setPendingRole]  = useState(null);      // 'host'|'client'
  const [joinCode,     setJoinCode]     = useState('');
  const [selectedApps, setSelectedApps] = useState(
    new Set(PRESET_APPS.slice(0, 3).map(a => a.pkg))          // default: first 3 preset
  );
  const [elapsed, setElapsed] = useState(0);

  // Elapsed timer
  useEffect(() => {
    if (vpn.status !== 'connected' || !vpn.connectedAt) { setElapsed(0); return; }
    const t = setInterval(() => setElapsed(Date.now() - vpn.connectedAt), 1000);
    return () => clearInterval(t);
  }, [vpn.status, vpn.connectedAt]);

  // Sync view with VPN status
  useEffect(() => {
    if (vpn.status === 'idle')   setView('idle');
    if (vpn.status === 'error')  setView('idle');
  }, [vpn.status]);

  // ── Handlers ────────────────────────────────────────────────────────

  const handleRoleSelect = (role) => {
    setPendingRole(role);
    if (role === 'client') {
      setView('joinEntry');
    } else {
      setView('appSelect');
    }
  };

  const handleStartHost = useCallback(async () => {
    const packages = Array.from(selectedApps);
    await dispatch(hostStart({
      appPackages: packages,
      hostId:      deviceId,
    }));
  }, [selectedApps, deviceId, dispatch]);

  const handleJoinClient = useCallback(async () => {
    const code = joinCode.trim().toUpperCase().replace(/\s/g, '');
    if (code.length < 8) {
      Alert.alert('Invalid Code', 'Please enter the 8-character session code (e.g. ABCD-EFGH).');
      return;
    }
    const packages = Array.from(selectedApps);
    await dispatch(clientJoin({
      sessionCode: code.includes('-') ? code : code.slice(0, 4) + '-' + code.slice(4),
      appPackages: packages,
      deviceId,
    }));
  }, [joinCode, selectedApps, deviceId, dispatch]);

  const handleDisconnect = useCallback(async () => {
    Alert.alert(
      'End Session',
      vpn.role === 'host'
        ? 'Ending the session will disconnect all clients. Continue?'
        : 'Leave this sharing session?',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Disconnect', style: 'destructive', onPress: () => dispatch(disconnect()) },
      ]
    );
  }, [vpn.role, dispatch]);

  const handleShareCode = useCallback(() => {
    if (!vpn.sessionCode) return;
    Share.share({ message: `Join my NetShare session: ${vpn.sessionCode}` });
  }, [vpn.sessionCode]);

  const handleCopyCode = useCallback(() => {
    if (!vpn.sessionCode) return;
    Clipboard.setString(vpn.sessionCode);
    Alert.alert('Copied!', 'Session code copied to clipboard.');
  }, [vpn.sessionCode]);

  const toggleApp = (pkg) => {
    setSelectedApps(prev => {
      const next = new Set(prev);
      if (next.has(pkg)) next.delete(pkg); else next.add(pkg);
      return next;
    });
  };

  // ── Render helpers ───────────────────────────────────────────────────

  const renderIdle = () => (
    <View style={s.centerBox}>
      <Text style={s.title}>NetShare</Text>
      <Text style={s.sub}>WireGuard-powered internet sharing</Text>

      <TouchableOpacity style={[s.btn, s.btnPrimary]} onPress={() => handleRoleSelect('host')}>
        <Text style={s.btnText}>📡  Share My Internet</Text>
      </TouchableOpacity>

      <TouchableOpacity style={[s.btn, s.btnSecondary]} onPress={() => handleRoleSelect('client')}>
        <Text style={[s.btnText, { color: '#333' }]}>🔗  Join a Session</Text>
      </TouchableOpacity>

      {vpn.errorMsg ? (
        <View style={s.errorBox}>
          <Text style={s.errorText}>⚠ {vpn.errorMsg}</Text>
        </View>
      ) : null}
    </View>
  );

  const renderAppSelect = () => (
    <View style={s.flex1}>
      <Text style={s.sectionTitle}>Select apps to tunnel</Text>
      <Text style={s.hint}>
        Only these apps' traffic goes through the shared connection.
        {'\n'}Your other apps (email, maps, etc.) stay on your own internet.
      </Text>

      <ScrollView style={s.appList}>
        {PRESET_APPS.map(app => (
          <View key={app.pkg} style={s.appRow}>
            <Switch
              value={selectedApps.has(app.pkg)}
              onValueChange={() => toggleApp(app.pkg)}
              trackColor={{ true: '#6C63FF' }}
            />
            <Text style={s.appLabel}>{app.label}</Text>
          </View>
        ))}
      </ScrollView>

      <Text style={s.selectedCount}>
        {selectedApps.size} app{selectedApps.size !== 1 ? 's' : ''} selected
      </Text>

      <TouchableOpacity
        style={[s.btn, s.btnPrimary, selectedApps.size === 0 && s.btnDisabled]}
        onPress={handleStartHost}
        disabled={selectedApps.size === 0}
      >
        <Text style={s.btnText}>Start Sharing</Text>
      </TouchableOpacity>

      <TouchableOpacity style={s.backBtn} onPress={() => setView('idle')}>
        <Text style={s.backBtnText}>← Back</Text>
      </TouchableOpacity>
    </View>
  );

  const renderJoinEntry = () => (
    <View style={s.centerBox}>
      <Text style={s.sectionTitle}>Enter session code</Text>
      <TextInput
        style={s.codeInput}
        value={joinCode}
        onChangeText={setJoinCode}
        placeholder="ABCD-EFGH"
        autoCapitalize="characters"
        maxLength={9}
        keyboardType="default"
      />

      <Text style={s.sectionTitle}>Select apps to tunnel</Text>
      <Text style={s.hint}>
        Only these apps will use the shared connection.{'\n'}
        Other apps stay on your own internet — no background drain.
      </Text>
      <ScrollView style={[s.appList, { maxHeight: 220 }]}>
        {PRESET_APPS.map(app => (
          <View key={app.pkg} style={s.appRow}>
            <Switch
              value={selectedApps.has(app.pkg)}
              onValueChange={() => toggleApp(app.pkg)}
              trackColor={{ true: '#6C63FF' }}
            />
            <Text style={s.appLabel}>{app.label}</Text>
          </View>
        ))}
      </ScrollView>

      <TouchableOpacity
        style={[s.btn, s.btnPrimary, !joinCode && s.btnDisabled]}
        onPress={handleJoinClient}
        disabled={!joinCode}
      >
        <Text style={s.btnText}>Join Session</Text>
      </TouchableOpacity>

      <TouchableOpacity style={s.backBtn} onPress={() => setView('idle')}>
        <Text style={s.backBtnText}>← Back</Text>
      </TouchableOpacity>
    </View>
  );

  const renderConnecting = () => (
    <View style={s.centerBox}>
      <ActivityIndicator size="large" color="#6C63FF" />
      <Text style={s.connectingText}>
        {vpn.role === 'host' ? 'Creating session…' : 'Joining session…'}
      </Text>
      <Text style={s.hint}>Setting up WireGuard tunnel</Text>
    </View>
  );

  const renderConnected = () => (
    <ScrollView contentContainerStyle={s.connectedContainer}>
      {/* Status pill */}
      <View style={s.statusPill}>
        <View style={s.statusDot} />
        <Text style={s.statusText}>Connected · {formatDuration(elapsed)}</Text>
      </View>

      {/* Role badge */}
      <Text style={s.roleBadge}>
        {vpn.role === 'host' ? '📡 Hosting' : '🔗 Client'}
      </Text>

      {/* Session code (host only) */}
      {vpn.role === 'host' && vpn.sessionCode ? (
        <View style={s.codeCard}>
          <Text style={s.codeLabel}>Session Code</Text>
          <Text style={s.codeValue}>{vpn.sessionCode}</Text>
          <View style={s.codeActions}>
            <TouchableOpacity style={s.codeBtn} onPress={handleCopyCode}>
              <Text style={s.codeBtnText}>Copy</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.codeBtn} onPress={handleShareCode}>
              <Text style={s.codeBtnText}>Share</Text>
            </TouchableOpacity>
          </View>
          <Text style={s.clientCount}>
            {vpn.clients.length} client{vpn.clients.length !== 1 ? 's' : ''} connected
          </Text>
          {vpn.clients.map(c => (
            <Text key={c.deviceId} style={s.clientRow}>
              ↳ {c.deviceId}  ·  {formatDuration(Date.now() - c.connectedAt)}
            </Text>
          ))}
        </View>
      ) : null}

      {/* Bandwidth */}
      <View style={s.statsRow}>
        <View style={s.statCard}>
          <Text style={s.statValue}>↑ {vpn.bandwidth.formattedUp}</Text>
          <Text style={s.statLabel}>Sent</Text>
        </View>
        <View style={s.statCard}>
          <Text style={s.statValue}>↓ {vpn.bandwidth.formattedDown}</Text>
          <Text style={s.statLabel}>Received</Text>
        </View>
      </View>

      {/* Tunnel IP */}
      <Text style={s.tunnelIp}>Tunnel IP: {vpn.clientIp}</Text>

      {/* Split-tunnel notice */}
      <View style={s.splitNotice}>
        <Text style={s.splitNoticeText}>
          🔒 Split-tunnel active — only {vpn.appPackages?.length || 0} selected app(s)
          use this connection. Your other apps are unaffected.
        </Text>
      </View>

      {/* Disconnect */}
      <TouchableOpacity style={[s.btn, s.btnDanger]} onPress={handleDisconnect}>
        <Text style={s.btnText}>
          {vpn.role === 'host' ? 'End Session' : 'Disconnect'}
        </Text>
      </TouchableOpacity>
    </ScrollView>
  );

  // ── Root render ──────────────────────────────────────────────────────
  const { status } = vpn;

  return (
    <View style={s.root}>
      {(status === 'connecting' || status === 'disconnecting') && renderConnecting()}
      {status === 'connected'                                  && renderConnected()}
      {(status === 'idle' || status === 'error') && view === 'idle'      && renderIdle()}
      {(status === 'idle' || status === 'error') && view === 'appSelect' && renderAppSelect()}
      {(status === 'idle' || status === 'error') && view === 'joinEntry' && renderJoinEntry()}
    </View>
  );
}

// ── Styles ────────────────────────────────────────────────────────────

const s = StyleSheet.create({
  root:              { flex: 1, backgroundColor: '#F5F6FA' },
  flex1:             { flex: 1, padding: 24 },
  centerBox:         { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24 },

  title:             { fontSize: 34, fontWeight: '800', color: '#1A1A2E', marginBottom: 6 },
  sub:               { fontSize: 15, color: '#888', marginBottom: 40, textAlign: 'center' },

  btn: {
    width: '100%', paddingVertical: 16, borderRadius: 14,
    alignItems: 'center', marginVertical: 8,
  },
  btnPrimary:        { backgroundColor: '#6C63FF' },
  btnSecondary:      { backgroundColor: '#E8E8F0', borderWidth: 1, borderColor: '#DDD' },
  btnDanger:         { backgroundColor: '#E74C3C' },
  btnDisabled:       { opacity: 0.45 },
  btnText:           { color: '#FFF', fontWeight: '700', fontSize: 16 },

  errorBox:          { backgroundColor: '#FDECEA', padding: 14, borderRadius: 10, marginTop: 16 },
  errorText:         { color: '#C0392B', fontSize: 14 },

  sectionTitle:      { fontSize: 18, fontWeight: '700', color: '#1A1A2E', marginBottom: 6, marginTop: 16 },
  hint:              { fontSize: 13, color: '#888', marginBottom: 12, lineHeight: 19 },
  selectedCount:     { fontSize: 13, color: '#6C63FF', marginBottom: 8 },

  appList:           { width: '100%' },
  appRow:            {
    flexDirection: 'row', alignItems: 'center',
    paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: '#EBEBEB',
  },
  appLabel:          { marginLeft: 14, fontSize: 15, color: '#333' },

  codeInput: {
    borderWidth: 2, borderColor: '#6C63FF', borderRadius: 12,
    padding: 14, fontSize: 24, fontWeight: '700', letterSpacing: 4,
    textAlign: 'center', width: '100%', marginBottom: 20, color: '#1A1A2E',
  },

  connectingText:    { marginTop: 20, fontSize: 18, fontWeight: '600', color: '#333' },

  connectedContainer:{ padding: 24, paddingBottom: 40 },

  statusPill: {
    flexDirection: 'row', alignItems: 'center',
    backgroundColor: '#E8F5E9', paddingVertical: 8, paddingHorizontal: 16,
    borderRadius: 20, alignSelf: 'center', marginBottom: 12,
  },
  statusDot:         { width: 10, height: 10, borderRadius: 5, backgroundColor: '#27AE60', marginRight: 8 },
  statusText:        { color: '#27AE60', fontWeight: '600', fontSize: 14 },

  roleBadge:         { textAlign: 'center', fontSize: 16, fontWeight: '700', color: '#6C63FF', marginBottom: 20 },

  codeCard: {
    backgroundColor: '#FFF', borderRadius: 16, padding: 20,
    marginBottom: 20, elevation: 3, shadowColor: '#000', shadowOpacity: 0.08,
    shadowRadius: 8, shadowOffset: { width: 0, height: 2 },
  },
  codeLabel:         { fontSize: 13, color: '#888', marginBottom: 4 },
  codeValue:         { fontSize: 32, fontWeight: '800', letterSpacing: 4, color: '#1A1A2E', marginBottom: 12 },
  codeActions:       { flexDirection: 'row', gap: 12, marginBottom: 12 },
  codeBtn:           { backgroundColor: '#6C63FF22', paddingVertical: 8, paddingHorizontal: 18, borderRadius: 8 },
  codeBtnText:       { color: '#6C63FF', fontWeight: '600' },
  clientCount:       { fontSize: 14, color: '#555', marginTop: 4 },
  clientRow:         { fontSize: 13, color: '#888', marginTop: 3 },

  statsRow:          { flexDirection: 'row', gap: 12, marginBottom: 16 },
  statCard: {
    flex: 1, backgroundColor: '#FFF', borderRadius: 14, padding: 16,
    alignItems: 'center', elevation: 2, shadowColor: '#000', shadowOpacity: 0.06,
    shadowRadius: 6, shadowOffset: { width: 0, height: 2 },
  },
  statValue:         { fontSize: 18, fontWeight: '700', color: '#1A1A2E' },
  statLabel:         { fontSize: 12, color: '#999', marginTop: 4 },

  tunnelIp:          { textAlign: 'center', fontSize: 13, color: '#AAA', marginBottom: 16 },

  splitNotice: {
    backgroundColor: '#EEF2FF', borderRadius: 12, padding: 14, marginBottom: 20,
  },
  splitNoticeText:   { fontSize: 13, color: '#4A46A0', lineHeight: 19 },

  backBtn:           { marginTop: 12, alignItems: 'center' },
  backBtnText:       { color: '#6C63FF', fontSize: 15, fontWeight: '600' },
});
