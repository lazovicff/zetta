import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Modal,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

import { getRecipient, registerBurnAddress } from '../api';
import { burnAddress, pubkey, randomSalt, schnorrSign } from '../crypto';
import { NETWORKS, type Network } from '../networks';
import { addEntry, getOrCreateIdentitySecret } from '../storage';

type Stage = 'network' | 'address';

const mono = Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' });

export function TopUpSheet({
  visible,
  onClose,
  onCreated,
}: {
  visible: boolean;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const [stage, setStage] = useState<Stage>('network');
  const [network, setNetwork] = useState<Network | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // reset to stage 1 every time the sheet opens
  useEffect(() => {
    if (visible) {
      setStage('network');
      setNetwork(null);
      setAddress(null);
      setError(null);
      setCopied(false);
    }
  }, [visible]);

  const pick = useCallback(
    async (n: Network) => {
      if (!n.enabled || busy) return;
      setNetwork(n);
      setBusy(true);
      setError(null);
      try {
        // TODO(multi-network): per-network server URL / chain id
        const recipient = await getRecipient();
        // one persistent identity key; a fresh salt mints a fresh burn address
        const secret = await getOrCreateIdentitySecret();
        const p = pubkey(secret);
        const salt = randomSalt();
        const addr = burnAddress(recipient, p.x, salt);
        // register first: the server only credits deposits to registered addresses,
        // so an unregistered address must never be shown or saved
        const sig = schnorrSign(secret, recipient);
        await registerBurnAddress({
          address: addr,
          pubkey: p,
          sigR: sig.sigR,
          sigZ: sig.sigZ,
          salt,
        });
        await addEntry({
          address: addr,
          pubkeyX: p.x.toString(10),
          salt: salt.toString(10),
          recipient: recipient.toString(10),
          createdAt: Date.now(),
        });

        setAddress(addr);
        setStage('address');
        await onCreated();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [busy, onCreated],
  );

  const copy = useCallback(async () => {
    if (!address) return;
    await Clipboard.setStringAsync(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [address]);

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={styles.overlay}>
        <Pressable style={styles.backdrop} onPress={onClose} />
        <View style={styles.sheet}>
          {stage === 'network' ? (
            <>
              <Text style={styles.title}>Top up</Text>
              <Text style={styles.subtitle}>Choose a network</Text>
              {NETWORKS.map((n) => (
                <Pressable
                  key={n.id}
                  style={[styles.networkRow, !n.enabled && styles.networkRowDisabled]}
                  onPress={() => pick(n)}
                  disabled={!n.enabled || busy}
                >
                  <Text
                    style={[styles.networkName, !n.enabled && styles.networkNameDisabled]}
                  >
                    {n.name}
                  </Text>
                  {busy && network?.id === n.id ? (
                    <ActivityIndicator color="#fff" />
                  ) : (
                    !n.enabled && <Text style={styles.soon}>Soon</Text>
                  )}
                </Pressable>
              ))}
              {error && <Text style={styles.error}>{error}</Text>}
            </>
          ) : (
            <>
              <Text style={styles.title}>Deposit address</Text>
              <Text style={styles.subtitle}>{network?.name}</Text>
              <View style={styles.addressCard}>
                <Text
                  style={styles.address}
                  numberOfLines={1}
                  adjustsFontSizeToFit
                  minimumFontScale={0.5}
                  selectable
                >
                  {address}
                </Text>
                <Pressable
                  style={({ pressed }) => [styles.copyButton, pressed && styles.dim]}
                  onPress={copy}
                >
                  <Text style={styles.copyText}>{copied ? 'Copied' : 'Copy'}</Text>
                </Pressable>
              </View>
              <Text style={styles.note}>
                This is a one-use deposit address — send funds to it only once. A fresh
                address is generated for every top up.
              </Text>
              <Pressable
                style={({ pressed }) => [styles.done, pressed && styles.dim]}
                onPress={onClose}
              >
                <Text style={styles.doneText}>Done</Text>
              </Pressable>
            </>
          )}
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
  title: { color: '#fff', fontSize: 18, fontWeight: '700' },
  subtitle: { color: '#888', fontSize: 13, marginTop: 4, marginBottom: 16 },
  networkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#1f1f24',
    borderRadius: 12,
    paddingVertical: 16,
    paddingHorizontal: 16,
    marginBottom: 10,
  },
  networkRowDisabled: { opacity: 0.45 },
  networkName: { color: '#eee', fontSize: 16, fontWeight: '600' },
  networkNameDisabled: { color: '#999' },
  soon: { color: '#777', fontSize: 12 },
  error: { color: '#ff7a7a', fontSize: 13, marginTop: 6 },
  addressRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1f1f24',
    borderRadius: 12,
    padding: 14,
    gap: 12,
  },
  addressCard: {
    backgroundColor: '#1f1f24',
    borderRadius: 12,
    padding: 14,
  },
  address: {
    color: '#eee',
    fontFamily: mono,
    fontSize: 15, // shrunk by adjustsFontSizeToFit until it fits on one line
    textAlign: 'center',
  },
  copyButton: {
    backgroundColor: '#e8e6e3',
    borderRadius: 8,
    paddingVertical: 10,
    alignItems: 'center',
    marginTop: 12,
  },
  copyText: { color: '#000', fontSize: 13, fontWeight: '600' },
  note: { color: '#b8902a', fontSize: 13, lineHeight: 19, marginTop: 14 },
  done: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 20,
  },
  doneText: { color: '#000', fontSize: 15, fontWeight: '600' },
  dim: { opacity: 0.6 },
});
