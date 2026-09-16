import * as Clipboard from 'expo-clipboard';
import { useCallback, useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { pubkey, userId } from '../crypto';
import { getIdentitySecret } from '../storage';

export function SettingsScreen() {
  const [pubkeyX, setPubkeyX] = useState<string | null>(null);
  const [userIdCopied, setUserIdCopied] = useState(false);

  useEffect(() => {
    (async () => {
      const secret = await getIdentitySecret();
      setPubkeyX(secret == null ? null : pubkey(secret).x.toString(10));
    })();
  }, []);

  const copyUserId = useCallback(async () => {
    if (!pubkeyX) return;
    await Clipboard.setStringAsync(userId(BigInt(pubkeyX)));
    setUserIdCopied(true);
    setTimeout(() => setUserIdCopied(false), 1500);
  }, [pubkeyX]);

  return (
    <View style={styles.root}>
      <Text style={styles.section}>User ID</Text>
      <View style={styles.card}>
        {pubkeyX ? (
          <>
            <Text style={styles.value} numberOfLines={1} ellipsizeMode="middle">
              {userId(BigInt(pubkeyX))}
            </Text>
            <Pressable
              style={({ pressed }) => [styles.copy, pressed && styles.dim]}
              onPress={copyUserId}
            >
              <Text style={styles.copyText}>{userIdCopied ? 'Copied' : 'Copy'}</Text>
            </Pressable>
          </>
        ) : (
          <Text style={styles.muted}>—</Text>
        )}
      </View>


      <Text style={styles.section}>Secret key</Text>
      <Pressable style={[styles.export, styles.exportDisabled]} disabled>
        <Text style={styles.exportText}>Export secret key</Text>
        <Text style={styles.exportNote}>Coming soon</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, paddingHorizontal: 16, paddingTop: 64 },
  section: { color: '#888', fontSize: 13, marginBottom: 10 },
  card: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1e',
    borderRadius: 10,
    padding: 14,
    marginBottom: 28,
    gap: 12,
  },
  value: { color: '#eee', fontSize: 13, flex: 1 },
  muted: { color: '#666', fontSize: 13 },
  copy: {
    backgroundColor: '#e8e6e3',
    borderRadius: 8,
    paddingVertical: 8,
    paddingHorizontal: 14,
  },
  copyText: { color: '#000', fontSize: 13, fontWeight: '600' },
  export: {
    backgroundColor: '#e8e6e3',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  exportDisabled: { opacity: 0.4 },
  exportText: { color: '#000', fontSize: 15, fontWeight: '600' },
  exportNote: { color: '#333', fontSize: 11, marginTop: 2 },
  dim: { opacity: 0.6 },
});
