/**
 * App.jsx — WireGuard Edition
 */

import React from 'react';
import { SafeAreaView, StatusBar, StyleSheet } from 'react-native';
import { Provider } from 'react-redux';
import store from './src/store/index';
import HomeScreen from './src/screens/HomeScreen';

export default function App() {
  return (
    <Provider store={store}>
      <SafeAreaView style={s.root}>
        <StatusBar barStyle="dark-content" backgroundColor="#F5F6FA" />
        <HomeScreen />
      </SafeAreaView>
    </Provider>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#F5F6FA' },
});
