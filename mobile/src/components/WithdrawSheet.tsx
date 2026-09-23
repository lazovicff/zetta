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

import { getBalance, getNextWithdrawNonce, requestWithdraw } from '../api';
import { pubkey, schnorrSignWithdraw } from '../crypto';
import { formatUsd, parseUsd } from '../format';
import { getOrCreateIdentitySecret } from '../storage';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function WithdrawSheet({
  visible,
  onClose,
  onCreated,
}: {
  visible: boolean;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [address, setAddress] = useState('');
  const [amount, setAmount] = useState('');
  const [balanceWei, setBalanceWei] = useState<bigint | null>(null);
  const [payoutWei, setPayoutWei] = useState<bigint | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (visible) {
      setAddress('');
      setAmount('');
      setError(null);
      setDone(false);
      setPayoutWei(null);
      getOrCreateIdentitySecret()
        .then((s) => getBalance(pubkey(s).x))
        .then(setBalanceWei)
        .catch(() => setBalanceWei(null));
    }
  }, [visible]);

  const submit = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const amountWei = parseUsd(amount);
      if (amountWei <= 0n) throw new Error('Amount must be above zero');
      const destination = address.trim();
      if (!ADDRESS_RE.test(destination)) throw new Error('Enter a valid 0x… address');

      const secret = await getOrCreateIdentitySecret();
      const pubkeyX = pubkey(secret).x;
      if ((await getBalance(pubkeyX)) < amountWei) {
        throw new Error('Insufficient balance');
      }

      const nonce = await getNextWithdrawNonce(pubkeyX);
      const sig = schnorrSignWithdraw(secret, amountWei, destination, BigInt(nonce));
      const res = await requestWithdraw({
        pubkeyX,
        amount: amountWei,
        destination,
        nonce,
        sigR: sig.sigR,
        sigZ: sig.sigZ,
      });

      setPayoutWei(BigInt(res.payout)); // payout = amount − fee
      setDone(true);
      await onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [address, amount, onCreated]);

  const fillMax = useCallback(() => {
    if (balanceWei == null) return;
    const whole = balanceWei / 10n ** 18n;
    const cents = (balanceWei % 10n ** 18n) / 10n ** 16n;
    Keyboard.dismiss();
    setAmount(`${whole}.${cents.toString().padStart(2, '0')}`);
  }, [balanceWei]);

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
            {done ? (
              <>
                <Text style={styles.title}>Withdrawal requested</Text>
                <Text style={styles.subtitle}>
                  {payoutWei != null ? `${formatUsd(payoutWei)} ` : ''}is on its way — payout
                  settles in the background.
                </Text>
                <Pressable
                  style={({ pressed }) => [styles.submit, pressed && styles.dim]}
                  onPress={onClose}
                >
                  <Text style={styles.submitText}>Done</Text>
                </Pressable>
              </>
            ) : (
              <>
                <Text style={styles.title}>Withdraw</Text>

                <View style={styles.labelRow}>
                  <Text style={styles.label}>Amount (USD)</Text>
                  <Pressable onPress={fillMax} hitSlop={8}>
                    <Text style={styles.available}>
                      Available: {balanceWei == null ? '—' : formatUsd(balanceWei)}
                    </Text>
                  </Pressable>
                </View>
                <TextInput
                  style={styles.input}
                  value={amount}
                  onChangeText={setAmount}
                  placeholder="25.00"
                  placeholderTextColor="#555"
                  keyboardType="decimal-pad"
                  editable={!busy}
                />

                <Text style={styles.label}>Destination address</Text>
                <TextInput
                  style={styles.input}
                  value={address}
                  onChangeText={setAddress}
                  placeholder="0x…"
                  placeholderTextColor="#555"
                  autoCapitalize="none"
                  autoCorrect={false}
                  editable={!busy}
                />

                <Text style={styles.note}>
                  The address receives the amount minus the withdraw fee.
                </Text>

                {error && <Text style={styles.error}>{error}</Text>}

                <Pressable
                  style={({ pressed }) => [styles.submit, (busy || pressed) && styles.dim]}
                  onPress={submit}
                  disabled={busy}
                >
                  {busy ? (
                    <ActivityIndicator color="#000" />
                  ) : (
                    <Text style={styles.submitText}>Withdraw</Text>
                  )}
                </Pressable>
              </>
            )}
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
  title: { color: '#fff', fontSize: 18, fontWeight: '700' },
  subtitle: { color: '#888', fontSize: 13, marginTop: 4, marginBottom: 16 },
  label: { color: '#888', fontSize: 12 },
  labelRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'baseline',
    marginBottom: 6,
  },
  available: { color: '#5b9dff', fontSize: 12 },
  input: {
    backgroundColor: '#1f1f24',
    borderRadius: 10,
    padding: 14,
    color: '#eee',
    fontSize: 16,
    marginBottom: 14,
  },
  note: { color: '#888', fontSize: 12, marginBottom: 14 },
  error: { color: '#ff7a7a', fontSize: 13, marginBottom: 8 },
  submit: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 4,
  },
  submitText: { color: '#000', fontSize: 15, fontWeight: '600' },
  dim: { opacity: 0.6 },
});
