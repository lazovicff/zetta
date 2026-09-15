import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Platform,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { getRecipient } from './src/api';
import { burnAddress, pubkey, randomScalar } from './src/crypto';
import { addEntry, listEntries } from './src/storage';
import type { BurnEntry } from './src/types';

export default function App() {
  const [entries, setEntries] = useState<BurnEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const reload = useCallback(async () => {
    setEntries(await listEntries());
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const create = useCallback(async () => {
    setBusy(true);
    try {
      const recipient = await getRecipient(); // current epoch from the server
      const secret = randomScalar();
      const p = pubkey(secret);
      const address = burnAddress(recipient, p.x);
      await addEntry(
        {
          address,
          pubkeyX: p.x.toString(10),
          recipient: recipient.toString(10),
          createdAt: Date.now(),
        },
        secret,
      );
      await reload();
    } catch (e) {
      Alert.alert('Could not create burn address', String(e));
    } finally {
      setBusy(false);
    }
  }, [reload]);

  return (
    <View style={styles.root}>
      <StatusBar style="light" />
      <Text style={styles.title}>Burn addresses</Text>

      <FlatList
        data={entries}
        keyExtractor={(e) => e.address}
        renderItem={({ item }) => (
          <View style={styles.row}>
            <Text style={styles.address} numberOfLines={1}>
              {item.address}
            </Text>
            <Text style={styles.meta}>
              {new Date(item.createdAt).toLocaleString()} · epoch …
              {item.recipient.slice(-8)}
            </Text>
          </View>
        )}
        ListEmptyComponent={
          <Text style={styles.empty}>
            No burn addresses yet.{'\n'}Create one, then deposit to it on-chain.
          </Text>
        }
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={async () => {
              setRefreshing(true);
              await reload();
              setRefreshing(false);
            }}
            tintColor="#bbb"
          />
        }
        contentContainerStyle={entries.length === 0 && styles.emptyContainer}
      />

      <Pressable
        style={({ pressed }) => [styles.button, (busy || pressed) && styles.buttonDim]}
        onPress={create}
        disabled={busy}
      >
        {busy ? (
          <ActivityIndicator color="#000" />
        ) : (
          <Text style={styles.buttonText}>New burn address</Text>
        )}
      </Pressable>
    </View>
  );
}

const mono = Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' });

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0e0e10', paddingHorizontal: 16, paddingTop: 64 },
  title: { color: '#fff', fontSize: 22, fontWeight: '700', marginBottom: 16 },
  row: {
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 10,
  },
  address: { color: '#eee', fontFamily: mono, fontSize: 14 },
  meta: { color: '#888', fontSize: 12, marginTop: 6 },
  emptyContainer: { flexGrow: 1, justifyContent: 'center' },
  empty: { color: '#666', textAlign: 'center', lineHeight: 22 },
  button: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    marginBottom: 32,
  },
  buttonDim: { opacity: 0.5 },
  buttonText: { color: '#000', fontSize: 16, fontWeight: '600' },
});
