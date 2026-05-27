/**
 * App.jsx — WireGuard Edition
 */

import React from 'react';
import {
  SafeAreaView, StatusBar, StyleSheet,
  View, Text, ScrollView, TouchableOpacity,
} from 'react-native';
import { Provider } from 'react-redux';
import store from './src/store/index';
import HomeScreen from './src/screens/HomeScreen';

// ── Error Boundary — shows crash reason ON SCREEN ─────────────────────
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { crashed: false, error: null, stack: null };
  }

  static getDerivedStateFromError(error) {
    return { crashed: true, error: error?.message || String(error) };
  }

  componentDidCatch(error, info) {
    this.setState({ stack: info?.componentStack || '' });
  }

  render() {
    if (!this.state.crashed) return this.props.children;
    return (
      <View style={eb.root}>
        <Text style={eb.title}>⚠ App Crashed</Text>
        <Text style={eb.label}>Error:</Text>
        <ScrollView style={eb.box}>
          <Text style={eb.msg}>{this.state.error}</Text>
        </ScrollView>
        <Text style={eb.label}>Stack:</Text>
        <ScrollView style={[eb.box, { maxHeight: 260 }]}>
          <Text style={eb.stack}>{this.state.stack}</Text>
        </ScrollView>
        <TouchableOpacity
          style={eb.btn}
          onPress={() => this.setState({ crashed: false, error: null, stack: null })}
        >
          <Text style={eb.btnText}>Retry</Text>
        </TouchableOpacity>
      </View>
    );
  }
}

const eb = StyleSheet.create({
  root:    { flex: 1, backgroundColor: '#1A1A2E', padding: 20, paddingTop: 60 },
  title:   { color: '#E74C3C', fontSize: 22, fontWeight: '800', marginBottom: 16 },
  label:   { color: '#AAA', fontSize: 13, marginTop: 12, marginBottom: 4 },
  box:     { backgroundColor: '#0D0D1A', borderRadius: 8, padding: 12, maxHeight: 160 },
  msg:     { color: '#FF6B6B', fontSize: 14, fontFamily: 'monospace' },
  stack:   { color: '#888', fontSize: 11, fontFamily: 'monospace' },
  btn:     { marginTop: 24, backgroundColor: '#6C63FF', borderRadius: 12,
             paddingVertical: 14, alignItems: 'center' },
  btnText: { color: '#FFF', fontWeight: '700', fontSize: 16 },
});

// ── App ───────────────────────────────────────────────────────────────
export default function App() {
  return (
    <ErrorBoundary>
      <Provider store={store}>
        <SafeAreaView style={s.root}>
          <StatusBar barStyle="dark-content" backgroundColor="#F5F6FA" />
          <HomeScreen />
        </SafeAreaView>
      </Provider>
    </ErrorBoundary>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#F5F6FA' },
});
