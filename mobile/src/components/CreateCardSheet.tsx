import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Keyboard,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import { getBalance, getNextCardNonce, orderCard } from '../api';
import { pubkey, schnorrSignOrder } from '../crypto';
import { parseUsd } from '../format';
import { getOrCreateIdentitySecret } from '../storage';

export function CreateCardSheet({
  visible,
  onClose,
  onCreated,
}: {
  visible: boolean;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [amount, setAmount] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (visible) {
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

      // single identity key — balance and lifetime spend are tracked per pubkey,
      // aggregated server-side across every registered burn address
      const secret = await getOrCreateIdentitySecret();
      const pubkeyX = pubkey(secret).x;
      if ((await getBalance(pubkeyX)) < amountWei) {
        throw new Error('Insufficient balance — top up first');
      }

      const nonce = await getNextCardNonce(pubkeyX);
      const sig = schnorrSignOrder(secret, amountWei, BigInt(nonce));
      await orderCard({
        pubkeyX,
        amount: amountWei,
        nonce,
        sigR: sig.sigR,
        sigZ: sig.sigZ,
      });

      await onCreated();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [amount, onCreated, onClose]);

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.flex}
      >
        <View style={styles.overlay}>
          <Pressable
            style={styles.backdrop}
            onPress={() => {
              Keyboard.dismiss();
              if (!busy) onClose();
            }}
          />
          <Pressable style={styles.sheet} onPress={Keyboard.dismiss} accessible={false}>
            <Text style={styles.title}>New card</Text>

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
          </Pressable>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
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
