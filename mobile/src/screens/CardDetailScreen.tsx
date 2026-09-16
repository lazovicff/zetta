import { Ionicons } from '@expo/vector-icons';
import { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { formatUsd } from '../format';
import type { CardEntry } from '../types';

// Legacy cards predate the cvc field — derive a stable stub so they still render.
function legacyCvc(id: string): string {
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return String(h % 1000).padStart(3, '0');
}

const group = (digits: string) => digits.replace(/(.{4})/g, '$1 ').trim();
const clamp01 = (x: number) => Math.min(1, Math.max(0, x));

function Bar({ frac, color, label, value }: { frac: number; color: string; label: string; value: string }) {
  return (
    <View style={styles.barRow}>
      <View style={styles.barTop}>
        <Text style={styles.barLabel}>{label}</Text>
        <Text style={styles.barValue}>{value}</Text>
      </View>
      <View style={styles.track}>
        <View style={[styles.fill, { width: `${clamp01(frac) * 100}%`, backgroundColor: color }]} />
      </View>
    </View>
  );
}

export function CardDetailScreen({ card, onBack }: { card: CardEntry; onBack: () => void }) {
  const [revealed, setRevealed] = useState(false);

  const total = BigInt(card.amountWei);
  const spent = BigInt(card.spentWei);
  const left = total - spent;
  const fundsFrac = total === 0n ? 0 : Number((left * 10_000n) / total) / 10_000;
  const lifeFrac = clamp01((card.expiresAt - Date.now()) / (card.expiresAt - card.createdAt));

  const cvc = card.cvc ?? legacyCvc(card.id);
  const exp = new Date(card.expiresAt);
  const expStr = `${String(exp.getMonth() + 1).padStart(2, '0')}/${String(exp.getFullYear()).slice(2)}`;
  const numberDisplay = revealed ? group(card.number) : `•••• •••• •••• ${card.number.slice(-4)}`;

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Pressable style={({ pressed }) => [styles.back, pressed && styles.dim]} onPress={onBack}>
          <Ionicons name="chevron-back" size={22} color="#fff" />
          <Text style={styles.backText}>Cards</Text>
        </Pressable>
      </View>

      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Card face */}
        <View style={styles.card}>
          <View style={styles.glow} />

          <View style={styles.cardTop}>
            <Text style={styles.brand}>ZETTA</Text>
            <Ionicons name="card" size={22} color="rgba(255,255,255,0.55)" />
          </View>

          <View style={styles.chip}>
            <View style={styles.chipLine} />
            <View style={styles.chipLine} />
          </View>

          <Text style={styles.cardNumber}>{numberDisplay}</Text>

          <View style={styles.cardBottom}>
            <View style={styles.metaCol}>
              <Text style={styles.metaLabel}>Card holder</Text>
              <Text style={styles.metaValue} numberOfLines={1}>{card.name}</Text>
            </View>
            <View style={styles.metaCol}>
              <Text style={styles.metaLabel}>Expires</Text>
              <Text style={styles.metaValue}>{expStr}</Text>
            </View>
            <View style={styles.metaCol}>
              <Text style={styles.metaLabel}>CVC</Text>
              <Text style={styles.metaValue}>{revealed ? cvc : '•••'}</Text>
            </View>
          </View>

          <Pressable
            style={({ pressed }) => [styles.reveal, pressed && styles.dim]}
            onPress={() => setRevealed((v) => !v)}
          >
            <Ionicons name={revealed ? 'eye-off' : 'eye'} size={16} color="#000" />
            <Text style={styles.revealText}>{revealed ? 'Hide' : 'Reveal'}</Text>
          </Pressable>
        </View>

        {/* Funds + validity */}
        <View style={styles.bars}>
          <Bar frac={fundsFrac} color="#e8e6e3" label="Funds left" value={formatUsd(left)} />
          <Bar frac={lifeFrac} color="#7d7d86" label="Valid until" value={expStr} />
        </View>

        {/* Transactions */}
        <Text style={styles.section}>Transactions</Text>
        <View style={styles.txEmpty}>
          <Ionicons name="receipt-outline" size={22} color="#555" />
          <Text style={styles.txEmptyText}>No transactions on this card yet.</Text>
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: '#0e0e10', paddingTop: 56 },
  header: { paddingHorizontal: 8, marginBottom: 12 },
  back: { flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start', padding: 8 },
  backText: { color: '#fff', fontSize: 16, fontWeight: '600', marginLeft: 2 },
  scroll: { paddingHorizontal: 16, paddingBottom: 32 },

  card: {
    backgroundColor: '#23232b',
    borderRadius: 20,
    padding: 22,
    overflow: 'hidden',
    minHeight: 210,
  },
  glow: {
    position: 'absolute',
    top: -60,
    right: -40,
    width: 200,
    height: 200,
    borderRadius: 100,
    backgroundColor: 'rgba(232,230,227,0.10)',
  },
  cardTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  brand: { color: '#fff', fontSize: 15, fontWeight: '800', letterSpacing: 3 },
  chip: {
    width: 42,
    height: 30,
    borderRadius: 6,
    backgroundColor: '#d8c88a',
    marginTop: 24,
    padding: 6,
    justifyContent: 'space-between',
  },
  chipLine: { height: 1, backgroundColor: 'rgba(0,0,0,0.35)' },
  cardNumber: {
    color: '#fff',
    fontSize: 20,
    letterSpacing: 2,
    fontVariant: ['tabular-nums'],
    marginTop: 18,
  },
  cardBottom: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 20,
    paddingRight: 64,
  },
  metaCol: { flex: 1, marginRight: 8 },
  metaLabel: { color: 'rgba(255,255,255,0.45)', fontSize: 10, marginBottom: 3 },
  metaValue: { color: '#fff', fontSize: 13, fontWeight: '600' },

  reveal: {
    position: 'absolute',
    right: 16,
    bottom: 16,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    backgroundColor: '#e8e6e3',
    borderRadius: 20,
    paddingVertical: 8,
    paddingHorizontal: 14,
  },
  revealText: { color: '#000', fontSize: 13, fontWeight: '600' },

  bars: {
    backgroundColor: '#1a1a1e',
    borderRadius: 16,
    padding: 18,
    marginTop: 20,
  },
  barRow: { marginBottom: 16 },
  barTop: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6 },
  barLabel: { color: '#888', fontSize: 12 },
  barValue: { color: '#eee', fontSize: 12, fontWeight: '600' },
  track: { height: 6, borderRadius: 3, backgroundColor: '#33333c', overflow: 'hidden' },
  fill: { height: 6, borderRadius: 3 },

  section: { color: '#888', fontSize: 13, marginTop: 24, marginBottom: 10 },
  txEmpty: {
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 16,
    paddingVertical: 32,
    gap: 8,
  },
  txEmptyText: { color: '#666', fontSize: 13 },
  dim: { opacity: 0.6 },
});
