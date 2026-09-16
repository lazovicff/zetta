import { useCallback, useEffect, useState } from 'react';
import { FlatList, Pressable, RefreshControl, StyleSheet, Text, View } from 'react-native';

import { CardView } from '../components/CardView';
import { CreateCardSheet } from '../components/CreateCardSheet';
import { listCards } from '../storage';
import type { CardEntry } from '../types';

export function CardsScreen() {
  const [cards, setCards] = useState<CardEntry[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);

  const reload = useCallback(async () => {
    setCards(await listCards());
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <View style={styles.root}>
      <Pressable
        style={({ pressed }) => [styles.create, pressed && styles.dim]}
        onPress={() => setSheetOpen(true)}
      >
        <Text style={styles.createText}>+ Create a new card</Text>
      </Pressable>

      <FlatList
        data={cards}
        keyExtractor={(c) => c.id}
        renderItem={({ item }) => <CardView card={item} />}
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
        contentContainerStyle={cards.length === 0 && styles.emptyContainer}
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
