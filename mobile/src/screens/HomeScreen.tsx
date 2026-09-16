import { useCallback, useEffect, useState } from 'react';
import {
  FlatList,
  Pressable,
  RefreshControl,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { pubkey } from '../crypto';
import { getBalance, getDeposits } from '../api';
import { TopUpSheet } from '../components/TopUpSheet';
import { formatUsd } from '../format';
import { listCards, listDepositRecords, listEntries, recordDeposits, getIdentitySecret } from '../storage';
import type { HistoryItem } from '../types';

export function HomeScreen() {
  const [balanceWei, setBalanceWei] = useState<bigint | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [topUpOpen, setTopUpOpen] = useState(false);

  const reload = useCallback(async () => {
    const entries = await listEntries();
    // single identity key: server aggregates across every registered burn address
    const secret = await getIdentitySecret();
    try {
      setBalanceWei(secret == null ? 0n : await getBalance(pubkey(secret).x));
    } catch {
      setBalanceWei(null);
    }

    // deposits: server is the source of truth; we stamp firstSeenAt locally,
    // cards: fully local — merge, newest first
    const owned = new Set(entries.map((e) => e.address.toLowerCase()));
    let deposits = await listDepositRecords();
    try {
      deposits = await recordDeposits(owned, await getDeposits());
    } catch {
      /* offline — keep last-known history */
    }
    const cards = await listCards();

    const items: HistoryItem[] = [
      ...cards.map((c) => ({
        id: `card-${c.id}`,
        kind: 'card' as const,
        title: c.name,
        subtitle: `Card load · ${new Date(c.createdAt).toLocaleString()}`,
        amountWei: -BigInt(c.amountWei), // a card load spends from the balance
        at: c.createdAt,
      })),
      ...deposits.map((d) => ({
        id: `dep-${d.address}-${d.treeIndex}`,
        kind: 'withdrawal' as const,
        title: 'Top up',
        subtitle: new Date(d.firstSeenAt).toLocaleString(),
        amountWei: BigInt(d.valueWei),
        at: d.firstSeenAt,
      })),
    ].sort((a, b) => b.at - a.at);
    setHistory(items);
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <View style={styles.root}>
      <Text style={styles.balanceLabel}>Total balance</Text>
      <Text style={styles.balance}>{balanceWei == null ? '—' : formatUsd(balanceWei)}</Text>

      <Pressable
        style={({ pressed }) => [styles.topUp, pressed && styles.dim]}
        onPress={() => setTopUpOpen(true)}
      >
        <Text style={styles.topUpText}>+ Top Up</Text>
      </Pressable>

      <Text style={styles.section}>History</Text>
      <FlatList
        data={history}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <View style={styles.row}>
            <View style={{ flex: 1, marginRight: 12 }}>
              <Text style={styles.rowTitle} numberOfLines={1}>
                {item.title}
              </Text>
              <Text style={styles.rowSub}>{item.subtitle}</Text>
            </View>
            <Text
              style={[styles.amount, item.amountWei < 0n ? styles.amountOut : styles.amountIn]}
            >
              {item.amountWei < 0n ? '−' : '+'}
              {formatUsd(item.amountWei < 0n ? -item.amountWei : item.amountWei)}
            </Text>
          </View>
        )}
        ListEmptyComponent={
          <Text style={styles.empty}>No activity yet.{'\n'}Tap + Top Up to get started.</Text>
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
        contentContainerStyle={history.length === 0 && styles.emptyContainer}
      />

      <TopUpSheet
        visible={topUpOpen}
        onClose={() => setTopUpOpen(false)}
        onCreated={reload}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  balanceLabel: { color: '#888', fontSize: 13 },
  balance: { color: '#fff', fontSize: 40, fontWeight: '700', marginTop: 4 },
  topUp: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 20,
    marginBottom: 24,
  },
  topUpText: { color: '#000', fontSize: 16, fontWeight: '600' },
  section: { color: '#888', fontSize: 13, marginBottom: 10 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 10,
  },
  rowTitle: { color: '#eee', fontSize: 15, fontWeight: '600' },
  rowSub: { color: '#888', fontSize: 12, marginTop: 4 },
  amount: { fontSize: 15, fontWeight: '700' },
  amountIn: { color: '#7dd88f' },
  amountOut: { color: '#eee' },
  emptyContainer: { flexGrow: 1, justifyContent: 'center' },
  empty: { color: '#666', textAlign: 'center', lineHeight: 22 },
  dim: { opacity: 0.5 },
});
