import { Pressable, StyleSheet, Text, View } from 'react-native';

import { cardCreatedMs, cardExpiry, cardNumber } from '../cards';
import { formatUsd } from '../format';
import type { CardOrderRow } from '../api';

const clamp01 = (x: number) => Math.min(1, Math.max(0, x));

function Bar({ frac, color }: { frac: number; color: string }) {
  return (
    <View style={styles.track}>
      <View style={[styles.fill, { width: `${clamp01(frac) * 100}%`, backgroundColor: color }]} />
    </View>
  );
}

export function CardView({ order, onPress }: { order: CardOrderRow; onPress?: () => void }) {
  const total = BigInt(order.amount); // no per-card spend feed from the stub provider
  const createdMs = cardCreatedMs(order);
  const exp = cardExpiry(createdMs);
  const lifeFrac = clamp01((exp.getTime() - Date.now()) / (exp.getTime() - createdMs));
  const expStr = `${String(exp.getMonth() + 1).padStart(2, '0')}/${String(exp.getFullYear()).slice(2)}`;
  const number = cardNumber(order.provider_ref);
  const masked = `${number.slice(0, 4)} •••• •••• ${number.slice(-4)}`;

  return (
    <Pressable
      style={({ pressed }) => [styles.card, pressed && styles.dim]}
      onPress={onPress}
    >
      <View style={styles.topRow}>
        <Text style={styles.name} numberOfLines={1}>
          Zetta card
        </Text>
        <Text style={styles.exp}>
          {order.status === 'succeeded' ? expStr : order.status}
        </Text>
      </View>
      <Text style={styles.number}>{masked}</Text>

      <View style={styles.barRow}>
        <Text style={styles.barLabel}>{formatUsd(total)} loaded</Text>
        <Bar frac={1} color="#e8e6e3" />
      </View>
      <View style={styles.barRow}>
        <Text style={styles.barLabel}>expires {expStr}</Text>
        <Bar frac={lifeFrac} color="#7d7d86" />
      </View>
    </Pressable>
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
  dim: { opacity: 0.6 },
});
