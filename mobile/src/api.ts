// Server endpoints (src/server.rs). URL comes from .env (EXPO_PUBLIC_*).

const SERVER_URL = process.env.EXPO_PUBLIC_SERVER_URL;

/** Current recipient epoch: trim246(keccak(chain_id ‖ exchange_addr ‖ tweak)). */
export async function getRecipient(): Promise<bigint> {
  if (!SERVER_URL) {
    throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  }
  const res = await fetch(`${SERVER_URL}/recipient`);
  if (!res.ok) throw new Error(`GET /recipient failed: ${res.status}`);
  const { recipient } = (await res.json()) as { recipient: string };
  return BigInt(recipient);
}

/** zDAI balance (wei, 18 decimals) for one pubkey, summed over all its burn addresses. */
export async function getBalance(pubkeyX: bigint): Promise<bigint> {
  if (!SERVER_URL) {
    throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  }
  const res = await fetch(`${SERVER_URL}/balance/${pubkeyX.toString(10)}`);
  if (!res.ok) throw new Error(`GET /balance failed: ${res.status}`);
  const { balance } = (await res.json()) as { balance: string };
  return BigInt(balance);
}

export interface StatusInfo {
  index: number; // global burn index
  root: string;
  deposits: number;
  registered: number;
}

export async function getStatus(): Promise<StatusInfo> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/status`);
  if (!res.ok) throw new Error(`GET /status failed: ${res.status}`);
  return (await res.json()) as StatusInfo;
}

export interface RemoteDeposit {
  address: string;
  value: string;
  tree_index: number;
}

export async function getDeposits(pubkeyX: bigint): Promise<RemoteDeposit[]> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/deposits/${pubkeyX.toString(10)}`);
  if (!res.ok) throw new Error(`GET /deposits failed: ${res.status}`);
  const { deposits } = (await res.json()) as { deposits: RemoteDeposit[] };
  return deposits;
}


export interface CardOrderResult {
  amount: string;
  provider: string;
  provider_ref: string;
  lifetime_spent: string;
}

export async function orderCard(req: {
  pubkeyX: bigint;
  amount: bigint; // wei
  nonce: number;  // per-user order nonce from /next_card_nonce
  sigR: { x: bigint; y: bigint };
  sigZ: bigint;
}): Promise<CardOrderResult> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/cards`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      pubkey_x: req.pubkeyX.toString(10),
      amount: req.amount.toString(10),
      nonce: req.nonce,
      sig_r: [req.sigR.x.toString(10), req.sigR.y.toString(10)],
      sig_z: req.sigZ.toString(10),
    }),
  });
  if (!res.ok) throw new Error(await res.text()); // server returns plain-text errors
  return (await res.json()) as CardOrderResult;
}


export async function getNextCardNonce(pubkeyX: bigint): Promise<number> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/next_card_nonce/${pubkeyX.toString(10)}`);
  if (!res.ok) throw new Error(`GET /next_card_nonce failed: ${res.status}`);
  const { nonce } = (await res.json()) as { nonce: number };
  return nonce;
}


/** Register a burn address + Schnorr ownership proof (server: register_inner).
 *  Deposits to unregistered addresses are NOT credited by the server. */
 export async function registerBurnAddress(req: {
   address: string;
   pubkey: { x: bigint; y: bigint };
   sigR: { x: bigint; y: bigint };
   sigZ: bigint;
   salt: bigint;
 }): Promise<void> {
   if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
   const res = await fetch(`${SERVER_URL}/register`, {
     method: 'POST',
     headers: { 'content-type': 'application/json' },
     body: JSON.stringify({
       address: req.address,
       pubkey: [req.pubkey.x.toString(10), req.pubkey.y.toString(10)],
       sig_r: [req.sigR.x.toString(10), req.sigR.y.toString(10)],
       sig_z: req.sigZ.toString(10),
       salt: req.salt.toString(10),
     }),
   });
   if (!res.ok) throw new Error(await res.text()); // server returns plain-text errors
 }

 export async function getNextWithdrawNonce(pubkeyX: bigint): Promise<number> {
   if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
   const res = await fetch(`${SERVER_URL}/next_withdraw_nonce/${pubkeyX.toString(10)}`);
   if (!res.ok) throw new Error(`GET /next_withdraw_nonce failed: ${res.status}`);
   const { nonce } = (await res.json()) as { nonce: number };
   return nonce;
 }

 export interface WithdrawResult {
   ref: string;
   amount: string;
   fee: string;
   payout: string;
   status: string; // 'pending' — the worker pays out asynchronously
 }

 /** POST /withdraw — debits `amount`; `destination` receives amount − fee. */
 export async function requestWithdraw(req: {
   pubkeyX: bigint;
   amount: bigint;      // wei, debited
   destination: string; // 0x + 40 hex
   nonce: number;       // per-user nonce from /next_withdraw_nonce
   sigR: { x: bigint; y: bigint };
   sigZ: bigint;
 }): Promise<WithdrawResult> {
   if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
   const res = await fetch(`${SERVER_URL}/withdraw`, {
     method: 'POST',
     headers: { 'content-type': 'application/json' },
     body: JSON.stringify({
       pubkey_x: req.pubkeyX.toString(10),
       amount: req.amount.toString(10),
       destination: req.destination,
       nonce: req.nonce,
       sig_r: [req.sigR.x.toString(10), req.sigR.y.toString(10)],
       sig_z: req.sigZ.toString(10),
     }),
   });
   if (!res.ok) throw new Error(await res.text()); // server returns plain-text errors
   return (await res.json()) as WithdrawResult;
 }

export interface CardOrderRow {
  provider_ref: string;
  amount: string; // wei loaded onto the card, decimal
  fee: string;    // wei, charged on TOP of amount
  status: 'pending' | 'succeeded' | 'failed' | 'closed';
  created_at: number; // unix seconds
}

/** Card orders for one pubkey — latest status per order, newest first. */
export async function getCardOrders(pubkeyX: bigint): Promise<CardOrderRow[]> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/cards/${pubkeyX.toString(10)}`);
  if (!res.ok) throw new Error(`GET /cards failed: ${res.status}`);
  const { orders } = (await res.json()) as { orders: CardOrderRow[] };
  return orders;
}

export interface WithdrawRow {
  ref: string;
  amount: string;      // wei debited, decimal (fee comes OUT of this)
  destination: string; // 0x…
  status: 'pending' | 'succeeded' | 'failed';
  created_at: number;  // unix seconds
}

/** Withdraw requests for one pubkey — latest status per request, newest first. */
export async function getWithdraws(pubkeyX: bigint): Promise<WithdrawRow[]> {
  if (!SERVER_URL) throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  const res = await fetch(`${SERVER_URL}/withdraws/${pubkeyX.toString(10)}`);
  if (!res.ok) throw new Error(`GET /withdraws failed: ${res.status}`);
  const { withdraws } = (await res.json()) as { withdraws: WithdrawRow[] };
  return withdraws;
}
