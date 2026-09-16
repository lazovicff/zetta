import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { CardsScreen } from './src/screens/CardsScreen';
import { HomeScreen } from './src/screens/HomeScreen';
import { SettingsScreen } from './src/screens/SettingsScreen';
import { getOrCreateIdentitySecret } from './src/storage';


type Tab = 'home' | 'cards' | 'settings';

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: 'home', label: 'Home', icon: '🏠' },
  { id: 'cards', label: 'Cards', icon: '💳' },
  { id: 'settings', label: 'Settings', icon: '⚙️' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('home');

  // create the wallet's signing key once, on first launch
  useEffect(() => {
    getOrCreateIdentitySecret().catch(() => {});
  }, []);

  return (
    <View style={styles.root}>
      <StatusBar style="light" />

      {/* conditional mount ⇒ each screen reloads its data on tab switch */}
      {tab === 'home' && <HomeScreen />}
      {tab === 'cards' && <CardsScreen />}
      {tab === 'settings' && <SettingsScreen />}

      <View style={styles.tabBar}>
        {TABS.map((t) => (
          <Pressable key={t.id} style={styles.tabItem} onPress={() => setTab(t.id)}>
            <Text style={[styles.tabIcon, tab !== t.id && styles.tabInactive]}>{t.icon}</Text>
            <Text style={[styles.tabLabel, tab === t.id && styles.tabLabelActive]}>
              {t.label}
            </Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0e0e10' },
  tabBar: {
    flexDirection: 'row',
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#2c2c33',
    backgroundColor: '#0e0e10',
    paddingBottom: 24,
    paddingTop: 8,
  },
  tabItem: { flex: 1, alignItems: 'center' },
  tabIcon: { fontSize: 20 },
  tabInactive: { opacity: 0.4 },
  tabLabel: { color: '#777', fontSize: 11, marginTop: 2 },
  tabLabelActive: { color: '#fff', fontWeight: '600' },
});
