// The ONLY locally persisted value: the wallet's identity secret, in the OS
// keystore (SecureStore). Everything else — burn addresses, cards, deposits,
// withdraws — is re-fetched from the server. Local state is disposable.

import * as SecureStore from 'expo-secure-store';

import { randomScalar } from './crypto';

const IDENTITY_KEY = 'zetta.identity';

/** The wallet's single signing key, created on first use, persisted across launches. */
export async function getOrCreateIdentitySecret(): Promise<bigint> {
  const existing = await getIdentitySecret();
  if (existing != null) return existing;
  const x = randomScalar();
  await SecureStore.setItemAsync(IDENTITY_KEY, x.toString(10));
  return x;
}

/** Identity secret, or null before first use. */
export async function getIdentitySecret(): Promise<bigint | null> {
  const v = await SecureStore.getItemAsync(IDENTITY_KEY);
  return v == null ? null : BigInt(v);
}
