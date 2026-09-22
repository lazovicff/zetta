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
  deadline: bigint; // global burn index; sig valid while index <= deadline
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
      deadline: req.deadline.toString(10),
      sig_r: [req.sigR.x.toString(10), req.sigR.y.toString(10)],
      sig_z: req.sigZ.toString(10),
    }),
  });
  if (!res.ok) throw new Error(await res.text()); // server returns plain-text errors
  return (await res.json()) as CardOrderResult;
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
