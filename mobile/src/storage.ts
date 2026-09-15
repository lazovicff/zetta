// Metadata list in AsyncStorage; secrets live in the OS keystore (SecureStore),
// keyed by the burn address they belong to. Secrets are never written to
// AsyncStorage and never logged.

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';

import type { BurnEntry } from './types';

const ENTRIES_KEY = 'zetta.entries.v1';
// SecureStore keys: [A-Za-z0-9._-] only — hex address is fine.
const secretKey = (address: string) => `zetta.secret.${address.toLowerCase()}`;

export async function listEntries(): Promise<BurnEntry[]> {
  const raw = await AsyncStorage.getItem(ENTRIES_KEY);
  return raw ? (JSON.parse(raw) as BurnEntry[]) : [];
}

/** Stores the secret first, then the entry — a crash mid-way leaves no orphaned entry. */
export async function addEntry(entry: BurnEntry, secret: bigint): Promise<void> {
  await SecureStore.setItemAsync(secretKey(entry.address), secret.toString(10));
  const entries = await listEntries();
  await AsyncStorage.setItem(ENTRIES_KEY, JSON.stringify([entry, ...entries]));
}

/** Only needed when signing/registration is added; the list UI never calls this. */
export async function getSecret(address: string): Promise<bigint | null> {
  const v = await SecureStore.getItemAsync(secretKey(address));
  return v == null ? null : BigInt(v);
}
