import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Modal,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { getBalance, getStatus, orderCard } from '../api';
import { pubkey, schnorrSignOrder } from '../crypto';
import { parseUsd } from '../format';
import { addCard, getOrCreateIdentitySecret } from '../storage';
import type { BurnEntry } from '../types';

/** Placeholder PAN — the 'stub' provider returns no card number yet. */
function stubCardNumber(): string {
  const buf = new Uint8Array(15);
  crypto.getRandomValues(buf);
  return '4' + [...buf].map((b) => (b % 10).toString()).join('');
}

const CARD_LIFETIME_MS = 3 * 365 * 24 * 3600 * 1000; // 3y, local convention

export function CreateCardSheet({
  visible,
  onClose,
  onCreated,
}: {
  visible: boolean;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (visible) {
      setName('');
      setAmount('');
      setError(null);
    }
  }, [visible]);

  const submit = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const amountWei = parseUsd(amount);
      if (amountWei <= 0n) throw new Error('Amount must be above zero');
      if (!name.trim()) throw new Error('Give the card a name');

      // single identity key — balance and lifetime spend are tracked per pubkey,
      // aggregated server-side across every registered burn address
      const secret = await getOrCreateIdentitySecret();
      const pubkeyX = pubkey(secret).x;
      if ((await getBalance(pubkeyX)) < amountWei) {
        throw new Error('Insufficient balance — top up first');
      }

      const { index } = await getStatus();
      const deadline = BigInt(index) + 1_000_000n; // server cap: index + 1_000_000
      const sig = schnorrSignOrder(secret, amountWei, deadline);
      const res = await orderCard({
        pubkeyX,
        amount: amountWei,
        deadline,
        sigR: sig.sigR,
        sigZ: sig.sigZ,
      });

      const now = Date.now();
      await addCard({
        id: res.provider_ref,
        name: name.trim(),
        number: stubCardNumber(),
        amountWei: amountWei.toString(10),
        spentWei: '0',
        pubkeyX: pubkeyX.toString(10),
        createdAt: now,
        expiresAt: now + CARD_LIFETIME_MS,
      });
      await onCreated();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [name, amount, onCreated, onClose]);

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={styles.overlay}>
        <Pressable style={styles.backdrop} onPress={busy ? undefined : onClose} />
        <View style={styles.sheet}>
          <Text style={styles.title}>New card</Text>

          <Text style={styles.label}>Card name</Text>
          <TextInput
            style={styles.input}
            value={name}
            onChangeText={setName}
            placeholder="e.g. Subscriptions"
            placeholderTextColor="#555"
            editable={!busy}
          />

          <Text style={styles.label}>Amount (USD)</Text>
          <TextInput
            style={styles.input}
            value={amount}
            onChangeText={setAmount}
            placeholder="25.00"
            placeholderTextColor="#555"
            keyboardType="decimal-pad"
            editable={!busy}
          />

          {error && <Text style={styles.error}>{error}</Text>}

          <Pressable
            style={({ pressed }) => [styles.create, (busy || pressed) && styles.dim]}
            onPress={submit}
            disabled={busy}
          >
            {busy ? (
              <ActivityIndicator color="#000" />
            ) : (
              <Text style={styles.createText}>Create card</Text>
            )}
          </Pressable>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  overlay: { flex: 1, justifyContent: 'flex-end' },
  backdrop: { ...StyleSheet.absoluteFill, backgroundColor: 'rgba(0,0,0,0.55)' },
  sheet: {
    backgroundColor: '#16161a',
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    padding: 20,
    paddingBottom: 36,
  },
  title: { color: '#fff', fontSize: 18, fontWeight: '700', marginBottom: 16 },
  label: { color: '#888', fontSize: 12, marginBottom: 6 },
  input: {
    backgroundColor: '#1f1f24',
    borderRadius: 10,
    padding: 14,
    color: '#eee',
    fontSize: 16,
    marginBottom: 14,
  },
  error: { color: '#ff7a7a', fontSize: 13, marginBottom: 8 },
  create: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 4,
  },
  createText: { color: '#000', fontSize: 15, fontWeight: '600' },
  dim: { opacity: 0.6 },
});
