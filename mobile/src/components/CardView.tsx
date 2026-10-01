import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { getCardDetails, type CardOrderRow } from '../api';
import { cardCreatedMs, cardExpiry, cardNumber } from '../cards';
import { pubkey } from '../crypto';
import { formatUsd } from '../format';
import { getIdentitySecret } from '../storage';

const clamp01 = (x: number) => Math.min(1, Math.max(0, x));

function Bar({ frac, color }: { frac: number; color: string }) {
  return (
    <View style={styles.track}>
      <View style={[styles.fill, { width: `${clamp01(frac) * 100}%`, backgroundColor: color }]} />
    </View>
  );
}

export function CardView({ order, onPress }: { order: CardOrderRow; onPress?: () => void }) {
  const [last4, setLast4] = useState<string | null>(null);
  const [liveExp, setLiveExp] = useState<string | null>(null);

  // Provider card data via the zetta server; stub display until ready/missing.
  useEffect(() => {
    if (order.status !== 'succeeded') return;
    let cancelled = false;
    (async () => {
      try {
        const secret = await getIdentitySecret();
        if (!secret) return;
        const d = await getCardDetails(pubkey(secret).x, order.provider_ref);
        if (cancelled || !d?.card_details) return;
        setLast4(d.card_details.card_number.slice(-4));
        setLiveExp(`${d.card_details.exp_month}/${d.card_details.exp_year.slice(-2)}`);
      } catch {
        // server/provider down — stub display stays
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [order.provider_ref, order.status]);

  const total = BigInt(order.amount);
  const createdMs = cardCreatedMs(order);
  const exp = cardExpiry(createdMs);
  const lifeFrac = clamp01((exp.getTime() - Date.now()) / (exp.getTime() - createdMs));
  const expStr = `${String(exp.getMonth() + 1).padStart(2, '0')}/${String(exp.getFullYear()).slice(2)}`;
  const masked = (() => {
    if (last4 != null) return `•••• •••• •••• ${last4}`;
    const n = cardNumber(order.provider_ref);
    return `${n.slice(0, 4)} •••• •••• ${n.slice(-4)}`;
  })();

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
          {order.status === 'succeeded' ? (liveExp ?? expStr) : order.status}
        </Text>
      </View>
      <Text style={styles.number}>{masked}</Text>

      <View style={styles.barRow}>
        <Text style={styles.barLabel}>{formatUsd(total)} loaded</Text>
        <Bar frac={1} color="#e8e6e3" />
      </View>
      <View style={styles.barRow}>
        <Text style={styles.barLabel}>expires {liveExp ?? expStr}</Text>
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
