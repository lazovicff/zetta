// Metadata lists in AsyncStorage; the wallet's single identity secret lives in
// the OS keystore (SecureStore). The secret is never written to AsyncStorage
// and never logged.

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as SecureStore from 'expo-secure-store';

import { randomScalar } from './crypto';
import type { BurnEntry, CardEntry, DepositRecord } from './types'

const ENTRIES_KEY = 'zetta.entries.v1';
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

export async function listEntries(): Promise<BurnEntry[]> {
  const raw = await AsyncStorage.getItem(ENTRIES_KEY);
  return raw ? (JSON.parse(raw) as BurnEntry[]) : [];
}

export async function addEntry(entry: BurnEntry): Promise<void> {
  const entries = await listEntries();
  await AsyncStorage.setItem(ENTRIES_KEY, JSON.stringify([entry, ...entries]));
}

const CARDS_KEY = 'zetta.cards.v1';
const DEPOSITS_KEY = 'zetta.deposits.v1';

export async function listCards(): Promise<CardEntry[]> {
  const raw = await AsyncStorage.getItem(CARDS_KEY);
  return raw ? (JSON.parse(raw) as CardEntry[]) : [];
}

export async function addCard(card: CardEntry): Promise<void> {
  const cards = await listCards();
  await AsyncStorage.setItem(CARDS_KEY, JSON.stringify([card, ...cards]));
}

export async function listDepositRecords(): Promise<DepositRecord[]> {
  const raw = await AsyncStorage.getItem(DEPOSITS_KEY);
  return raw ? (JSON.parse(raw) as DepositRecord[]) : [];
}

/** Adds newly observed deposits for owned addresses; returns the full list (new first). */
export async function recordDeposits(
  ownedAddresses: Set<string>,
  remote: { address: string; value: string; tree_index: number }[],
): Promise<DepositRecord[]> {
  const known = await listDepositRecords();
  const knownKeys = new Set(known.map((d) => `${d.address}:${d.treeIndex}:${d.valueWei}`));
  const fresh = remote
    .filter((r) => ownedAddresses.has(r.address.toLowerCase()))
    .filter((r) => !knownKeys.has(`${r.address.toLowerCase()}:${r.tree_index}:${r.value}`))
    .map((r) => ({
      address: r.address.toLowerCase(),
      valueWei: r.value,
      treeIndex: r.tree_index,
      firstSeenAt: Date.now(),
    }));
  if (fresh.length === 0) return known;
  const all = [...fresh, ...known];
  await AsyncStorage.setItem(DEPOSITS_KEY, JSON.stringify(all));
  return all;
}
