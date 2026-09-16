import { StyleSheet, Text, View } from 'react-native';

import { formatUsd } from '../format';
import type { CardEntry } from '../types';

const clamp01 = (x: number) => Math.min(1, Math.max(0, x));

function Bar({ frac, color }: { frac: number; color: string }) {
  return (
    <View style={styles.track}>
      <View style={[styles.fill, { width: `${clamp01(frac) * 100}%`, backgroundColor: color }]} />
    </View>
  );
}

export function CardView({ card }: { card: CardEntry }) {
  const total = BigInt(card.amountWei);
  const left = total - BigInt(card.spentWei);
  const fundsFrac = total === 0n ? 0 : Number((left * 10_000n) / total) / 10_000;
  const lifeFrac = clamp01(
    (card.expiresAt - Date.now()) / (card.expiresAt - card.createdAt),
  );
  const exp = new Date(card.expiresAt);
  const expStr = `${String(exp.getMonth() + 1).padStart(2, '0')}/${String(exp.getFullYear()).slice(2)}`;
  const masked = `${card.number.slice(0, 4)} •••• •••• ${card.number.slice(-4)}`;

  return (
    <View style={styles.card}>
      <View style={styles.topRow}>
        <Text style={styles.name} numberOfLines={1}>
          {card.name}
        </Text>
        <Text style={styles.exp}>{expStr}</Text>
      </View>
      <Text style={styles.number}>{masked}</Text>

      <View style={styles.barRow}>
        <Text style={styles.barLabel}>{formatUsd(left)} left</Text>
        <Bar frac={fundsFrac} color="#e8e6e3" />
      </View>
      <View style={styles.barRow}>
        <Text style={styles.barLabel}>expires {expStr}</Text>
        <Bar frac={lifeFrac} color="#7d7d86" />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#1f1f26',
    borderRadius: 16,
    padding: 18,
    marginBottom: 14,
  },
  topRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  name: { color: '#fff', fontSize: 16, fontWeight: '700', flex: 1, marginRight: 8 },
  exp: { color: '#888', fontSize: 12 },
  number: { color: '#ccc', fontSize: 15, letterSpacing: 1, marginTop: 10, marginBottom: 14 },
  barRow: { marginTop: 8 },
  barLabel: { color: '#888', fontSize: 11, marginBottom: 4 },
  track: { height: 5, borderRadius: 3, backgroundColor: '#33333c', overflow: 'hidden' },
  fill: { height: 5, borderRadius: 3 },
});
