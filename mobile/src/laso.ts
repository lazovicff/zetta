// Dev client for the mock Laso API (src/bin/mock-laso.rs). When
// EXPO_PUBLIC_LASO_URL is set, card details come from the mock instead of the
// stubs in cards.ts.
//
// The x402 payment header below is UNSIGNED JSON — accepted only by the mock,
// never by laso.finance (which verifies on-chain). Do not point this at production.

import * as SecureStore from 'expo-secure-store';

const LASO_URL = process.env.EXPO_PUBLIC_LASO_URL;
/** Pays every order in dev; becomes the mock's user_id for all cards. */
const DEV_WALLET = '0x1111111111111111111111111111111111111111';
const LINK_PREFIX = 'zetta.laso.';

export function lasoEnabled(): boolean {
  return LASO_URL != null && LASO_URL !== '';
}

function base(): string {
  if (!lasoEnabled()) throw new Error('EXPO_PUBLIC_LASO_URL is not set — check mobile/.env');
  return LASO_URL;
}

// ---- types (mirror laso.finance /openapi.json) ----

export interface LasoCardData {
  card_id: string;
  card_type: string;
  usd_amount: number;
  timestamp: number;
  status: 'pending' | 'ready' | 'queued' | 'complete' | 'refunded' | 'archived';
  card_details?: {
    card_number: string;
    exp_month: string; // "07"
    exp_year: string; // "2029"
    cvv: string;
    available_balance: number;
    billing_address: {
      name: string;
      line_1: string;
      line_2: string;
      city: string;
      state: string;
      zip: string;
      country: string;
      required: boolean;
    } | null;
  };
  transactions?: { amount: number; date: string; description: string; is_credit: boolean }[];
}

export interface LasoCardLink {
  cardId: string;
  idToken: string;
  refreshToken: string;
}

interface LasoAuth {
  id_token: string;
  refresh_token: string;
}

// ---- link persistence: zetta provider_ref -> laso card ----
// SecureStore on top of the identity secret; the mock is in-memory, so links
// may outlive the cards they point at — getCardLink misses degrade to stubs.

export async function saveCardLink(providerRef: string, link: LasoCardLink): Promise<void> {
  await SecureStore.setItemAsync(LINK_PREFIX + providerRef, JSON.stringify(link));
}

export async function getCardLink(providerRef: string): Promise<LasoCardLink | null> {
  const v = await SecureStore.getItemAsync(LINK_PREFIX + providerRef);
  return v ? (JSON.parse(v) as LasoCardLink) : null;
}

// ---- API ----

/** x402 handshake: GET /get-card -> 402 -> replay with (unsigned) payment. */
export async function lasoOrderCard(amountUsd: number): Promise<LasoCardLink> {
  const url = `${base()}/get-card?amount=${amountUsd}`;
  const first = await fetch(url);
  if (first.status !== 402) {
    throw new Error(`laso /get-card: expected 402 challenge, got ${first.status}`);
  }
  const encoded = first.headers.get('payment-required');
  if (!encoded) throw new Error('laso /get-card: missing PAYMENT-REQUIRED header');
  const challenge = JSON.parse(b64decode(encoded));
  const accept =
    challenge.accepts?.find((a: { network?: string }) => a.network === 'eip155:8453') ??
    challenge.accepts?.[0];
  if (!accept) throw new Error('laso /get-card: challenge has no payment options');

  const payment = {
    x402Version: 2,
    accepted: accept,
    payload: {
      authorization: {
        from: DEV_WALLET,
        to: accept.payTo,
        value: accept.amount,
        validAfter: '0',
        validBefore: '0',
        nonce: '0x00',
      },
    },
  };
  const paid = await fetch(url, {
    headers: { 'PAYMENT-SIGNATURE': b64encode(JSON.stringify(payment)) },
  });
  if (!paid.ok) {
    throw new Error(`laso /get-card payment rejected: ${paid.status} ${await paid.text()}`);
  }
  const body = (await paid.json()) as {
    auth: LasoAuth;
    card: { card_id: string };
  };
  return {
    cardId: body.card.card_id,
    idToken: body.auth.id_token,
    refreshToken: body.auth.refresh_token,
  };
}

/** One card fetch. On 401 (mock restarted, tokens wiped) re-auths and retries once. */
export async function lasoCardData(
  link: LasoCardLink,
  providerRef: string,
): Promise<{ data: LasoCardData; link: LasoCardLink }> {
  const fetchIt = (token: string) =>
    fetch(`${base()}/get-card-data?card_id=${link.cardId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  let res = await fetchIt(link.idToken);
  if (res.status === 401) {
    const auth = await lasoAuth();
    link = { ...link, idToken: auth.id_token, refreshToken: auth.refresh_token };
    await saveCardLink(providerRef, link);
    res = await fetchIt(link.idToken);
  }
  if (!res.ok) throw new Error(`laso /get-card-data failed: ${res.status}`);
  return { data: (await res.json()) as LasoCardData, link };
}

/** Poll every 2s (docs: details take ~7-10s) until the card is ready, ~40s max. */
export async function lasoWaitForCard(
  link: LasoCardLink,
  providerRef: string,
): Promise<LasoCardData> {
  for (let i = 0; i < 20; i++) {
    const res = await lasoCardData(link, providerRef);
    link = res.link;
    if (res.data.status === 'ready' || res.data.status === 'complete') return res.data;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`laso card ${link.cardId} not ready after ~40s`);
}

/** Free auth: mint id/refresh tokens for the dev wallet (mock accepts any SIWX blob). */
async function lasoAuth(): Promise<LasoAuth> {
  const siwx = b64encode(
    JSON.stringify({
      domain: base().replace(/^https?:\/\//, ''),
      address: DEV_WALLET,
      statement: 'Sign in to Laso Finance',
      nonce: `mock-${Date.now()}`,
    }),
  );
  const res = await fetch(`${base()}/auth`, { headers: { 'SIGN-IN-WITH-X': siwx } });
  if (!res.ok) throw new Error(`laso /auth failed: ${res.status}`);
  return ((await res.json()) as { auth: LasoAuth }).auth;
}

// ---- base64, ASCII-only (RN has no atob/btoa) ----

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64encode(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i += 3) {
    const a = input.charCodeAt(i);
    const b = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    const c = i + 2 < input.length ? input.charCodeAt(i + 2) : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < input.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < input.length ? B64[n & 63] : '=';
  }
  return out;
}

function b64decode(input: string): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const raw of input) {
    const ch = raw === '-' ? '+' : raw === '_' ? '/' : raw;
    if (ch === '=') break;
    const v = B64.indexOf(ch);
    if (v < 0) throw new Error('bad base64');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((acc >> bits) & 0xff);
    }
  }
  return out;
}
