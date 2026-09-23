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
import { CardOrderRow, getBalance, getCardOrders, getDeposits, getWithdraws, RemoteDeposit, WithdrawRow } from '../api';
import { TopUpSheet } from '../components/TopUpSheet';
import { WithdrawSheet } from '../components/WithdrawSheet';
import { formatUsd } from '../format';
import { getIdentitySecret } from '../storage';
import type { HistoryItem } from '../types';

export function HomeScreen() {
  const [balanceWei, setBalanceWei] = useState<bigint | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [topUpOpen, setTopUpOpen] = useState(false);
  const [withdrawOpen, setWithdrawOpen] = useState(false);

  const reload = useCallback(async () => {
    const secret = await getIdentitySecret();
    let deposits: RemoteDeposit[] = [];
    let orders: CardOrderRow[] = [];
    let withdraws: WithdrawRow[] = [];
    if (secret != null) {
      const pkX = pubkey(secret).x;
      try {
        setBalanceWei(await getBalance(pkX));
      } catch {
        setBalanceWei(null);
      }
      try {
        deposits = await getDeposits(pkX);
      } catch (e) {
        console.warn('getDeposits failed', e);
      }
      try {
        orders = await getCardOrders(pkX);
      } catch (e) {
        console.warn('getCardOrders failed', e);
      }
      try {
        withdraws = await getWithdraws(pkX);
      } catch (e) {
        console.warn('getWithdraws failed', e);
      }
    } else {
      setBalanceWei(0n);
    }

    // deposits first (newest leaf first), then card orders (newest first) — no
    // common time axis between the two.
    const items: HistoryItem[] = [
      ...deposits
        .sort((a, b) => b.tree_index - a.tree_index)
        .map((d) => ({
          id: `dep-${d.address}-${d.tree_index}`,
          kind: 'deposit' as const,
          title: 'Top up',
          subtitle: `${d.address.slice(0, 7)}…${d.address.slice(-5)}`,
          amountWei: BigInt(d.value),
          at: d.tree_index,
        })),
      ...orders
        .filter((o) => o.status !== 'failed') // failed released the reservation — nothing was spent
        .map((o) => ({
          id: `card-${o.provider_ref}`,
          kind: 'card' as const,
          title: 'Card load',
          subtitle: new Date(o.created_at * 1000).toLocaleString(),
          amountWei: -(BigInt(o.amount) + BigInt(o.fee)), // fee is charged ON TOP of the load
          at: o.created_at * 1000,
        })),
      ...withdraws
        .filter((w) => w.status !== 'failed') // failed released the reservation — nothing was spent
        .map((w) => ({
          id: `wd-${w.ref}`,
          kind: 'withdraw' as const,
          title: 'Withdraw',
          subtitle: `${w.destination.slice(0, 7)}…${w.destination.slice(-5)}`,
          amountWei: -BigInt(w.amount), // fee comes OUT of this amount
          at: w.created_at * 1000,
        })),
    ];
    setHistory(items);
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return (
    <View style={styles.root}>
      <Text style={styles.balanceLabel}>Total balance</Text>
      <Text style={styles.balance}>{balanceWei == null ? '—' : formatUsd(balanceWei)}</Text>

      <View style={styles.actions}>
        <Pressable
          style={({ pressed }) => [styles.action, styles.topUp, pressed && styles.dim]}
          onPress={() => setTopUpOpen(true)}
        >
          <Text style={styles.topUpText}>+ Top Up</Text>
        </Pressable>
        <Pressable
          style={({ pressed }) => [styles.action, styles.withdraw, pressed && styles.dim]}
          onPress={() => setWithdrawOpen(true)}
        >
          <Text style={styles.withdrawText}>− Withdraw</Text>
        </Pressable>
      </View>

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
      <WithdrawSheet
        visible={withdrawOpen}
        onClose={() => setWithdrawOpen(false)}
        onCreated={reload}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  balanceLabel: { color: '#888', fontSize: 13 },
  balance: { color: '#fff', fontSize: 40, fontWeight: '700', marginTop: 4 },
  actions: { flexDirection: 'row', gap: 10, marginTop: 20, marginBottom: 24 },
  action: { flex: 1, borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
  topUp: { backgroundColor: '#e8e6e3' },
  withdraw: { backgroundColor: 'transparent', borderWidth: 1, borderColor: '#3a3a40' },
  topUpText: { color: '#000', fontSize: 16, fontWeight: '600' },
  withdrawText: { color: '#eee', fontSize: 16, fontWeight: '600' },
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
