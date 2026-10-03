import { Ionicons } from '@expo/vector-icons';
import { useEffect, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { cardCreatedMs, cardCvc, cardExpiry, cardNumber } from '../cards';
import { formatUsd } from '../format';
import { getCardDetails, type CardOrderRow, type RemoteCardDetails } from '../api';
import { pubkey } from '../crypto';
import { getIdentitySecret } from '../storage';

const group = (digits: string) => digits.replace(/(.{4})/g, '$1 ').trim();
const clamp01 = (x: number) => Math.min(1, Math.max(0, x));
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

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

export function CardDetailScreen({ order, onBack }: { order: CardOrderRow; onBack: () => void }) {
  const [revealed, setRevealed] = useState(false);
  const [remote, setRemote] = useState<RemoteCardDetails | null>(null);

  // Provider card data via the zetta server, polled until ready. null (stub-era
  // order) or error -> stub display stays.
  useEffect(() => {
    if (order.status !== 'succeeded') return;
    let cancelled = false;
    (async () => {
      try {
        const secret = await getIdentitySecret();
        if (!secret) return;
        const pkX = pubkey(secret).x;
        for (let i = 0; i < 20 && !cancelled; i++) {
          const d = await getCardDetails(pkX, order.provider_ref);
          if (cancelled) return;
          if (d == null) return; // stub-era order
          setRemote(d);
          if (d.status === 'ready' || d.status === 'complete') return;
          await sleep(2000);
        }
      } catch {
        // server/provider down — stub display stays
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [order.provider_ref, order.status]);

  const details = remote?.card_details;

  // Stub-derived fallbacks (pre-provider orders).
  const totalWei = BigInt(order.amount);
  const stubCreatedMs = cardCreatedMs(order);
  const stubExp = cardExpiry(stubCreatedMs);
  const stubExpStr = `${String(stubExp.getMonth() + 1).padStart(2, '0')}/${String(stubExp.getFullYear()).slice(2)}`;

  const number = details?.card_number ?? cardNumber(order.provider_ref);
  const cvc = details?.cvv ?? cardCvc(order.provider_ref);
  const expStr = details ? `${details.exp_month}/${details.exp_year.slice(-2)}` : stubExpStr;
  const numberDisplay = revealed ? group(number) : `•••• •••• •••• ${number.slice(-4)}`;

  const createdMs = remote?.timestamp ?? stubCreatedMs;
  const expEndMs = details
    ? new Date(Number(details.exp_year), Number(details.exp_month), 1).getTime() // first day after exp month
    : stubExp.getTime();
  const lifeFrac = clamp01((expEndMs - Date.now()) / (expEndMs - createdMs));

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
              <Text style={styles.metaValue} numberOfLines={1}>
                {'Zetta card'}
              </Text>
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

        {/* Billing address (what to enter when a merchant asks at checkout) */}
        {revealed && details?.billing_address && (
          <>
            <Text style={styles.section}>Billing address</Text>
            <View style={styles.billing}>
              <Text style={styles.billingText}>{details.billing_address.name}</Text>
              <Text style={styles.billingText}>
                {[details.billing_address.line_1, details.billing_address.line_2]
                  .filter(Boolean)
                  .join(', ')}
              </Text>
              <Text style={styles.billingText}>
                {details.billing_address.city}, {details.billing_address.state}{' '}
                {details.billing_address.zip}, {details.billing_address.country}
              </Text>
            </View>
          </>
        )}

        {/* Funds + validity */}
        <View style={styles.bars}>
          {remote && details ? (
            <Bar
              frac={details.available_balance / (remote.usd_amount ?? details.available_balance)}
              color="#e8e6e3"
              label="Balance"
              value={
                remote.usd_amount != null
                  ? `$${details.available_balance.toFixed(2)} of $${remote.usd_amount.toFixed(2)}`
                  : `$${details.available_balance.toFixed(2)}`
              }
            />
          ) : (
            <Bar frac={1} color="#e8e6e3" label="Loaded" value={formatUsd(totalWei)} />
          )}
          <Bar frac={lifeFrac} color="#7d7d86" label="Valid until" value={expStr} />
        </View>

        {/* Transactions */}
        <Text style={styles.section}>Transactions</Text>
        {remote?.transactions?.length ? (
          <View style={styles.txList}>
            {remote.transactions.map((t, i) => (
              <View key={i} style={styles.txRow}>
                <Text style={styles.txDesc} numberOfLines={1}>
                  {t.description}
                </Text>
                <Text style={styles.txAmt}>
                  {t.is_credit ? '+' : '−'}${Math.abs(t.amount).toFixed(2)}
                </Text>
              </View>
            ))}
          </View>
        ) : (
          <View style={styles.txEmpty}>
            <Ionicons name="receipt-outline" size={22} color="#555" />
            <Text style={styles.txEmptyText}>No transactions on this card yet.</Text>
          </View>
        )}
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
  billing: { backgroundColor: '#1a1a1e', borderRadius: 16, padding: 16, gap: 4 },
  billingText: { color: '#ddd', fontSize: 13 },
  txList: { backgroundColor: '#1a1a1e', borderRadius: 16, paddingVertical: 4 },
  txRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  txDesc: { color: '#ddd', fontSize: 13, flex: 1, marginRight: 12 },
  txAmt: { color: '#eee', fontSize: 13, fontVariant: ['tabular-nums'] },
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
