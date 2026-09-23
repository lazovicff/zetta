import { useCallback, useEffect, useState } from 'react';
import { FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from 'react-native';

import { CardOrderRow, getCardOrders } from '../api';
import { CardView } from '../components/CardView';
import { CreateCardSheet } from '../components/CreateCardSheet';
import { pubkey } from '../crypto';
import { getIdentitySecret } from '../storage';
import { CardDetailScreen } from './CardDetailScreen';

export function CardsScreen() {
  const [orders, setOrders] = useState<CardOrderRow[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [selected, setSelected] = useState<CardOrderRow | null>(null);

  const reload = useCallback(async () => {
    const secret = await getIdentitySecret();
    if (secret == null) {
      setOrders([]);
      return;
    }
    try {
      const rows = await getCardOrders(pubkey(secret).x);
      setOrders(rows.filter((o) => o.status !== 'failed'));
    } catch (e) {
      console.warn('getCardOrders failed', e); // keep last-known list
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  if (selected) {
    return <CardDetailScreen order={selected} onBack={() => setSelected(null)} />;
  }

  return (
    <View style={styles.root}>
      <Pressable
        style={({ pressed }) => [styles.create, pressed && styles.dim]}
        onPress={() => setSheetOpen(true)}
      >
        <Text style={styles.createText}>+ Create a new card</Text>
      </Pressable>

      <FlatList
        data={orders}
        keyExtractor={(o) => o.provider_ref}
        renderItem={({ item }) => <CardView order={item} onPress={() => setSelected(item)} />}
        ListEmptyComponent={
          <Text style={styles.empty}>No cards yet.{'\n'}Create one to start spending.</Text>
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
        contentContainerStyle={orders.length === 0 && styles.emptyContainer}
      />

      <CreateCardSheet
        visible={sheetOpen}
        onClose={() => setSheetOpen(false)}
        onCreated={reload}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  create: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginBottom: 20,
  },
  createText: { color: '#000', fontSize: 16, fontWeight: '600' },
  emptyContainer: { flexGrow: 1, justifyContent: 'center' },
  empty: { color: '#666', textAlign: 'center', lineHeight: 22 },
  dim: { opacity: 0.5 },
});
