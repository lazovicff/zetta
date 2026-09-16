export interface BurnEntry {
  /** 0x + 40 hex chars — the burn address shown in the list. */
  address: string;
  /** x-coordinate of the pubkey, decimal (grumpkin Fq). */
  pubkeyX: string;
  /** Burn preimage salt, decimal (bn254 Fr). Required to rebuild withdraw witnesses. */
  salt: string;
  /** Recipient epoch this address was derived under, decimal (bn254 Fr). */
  recipient: string;
  /** Unix ms. */
  createdAt: number;
}


export interface CardEntry {
  /** provider_ref ('stub-…') — unique. */
  id: string;
  name: string;
  /** 16 digits — STUB PAN until a real provider returns one. */
  number: string;
  /** Initial load, decimal wei. */
  amountWei: string;
  /** No per-card tx feed yet — stays '0'. */
  spentWei: string;
  /** Key that funded the card, decimal. */
  pubkeyX: string;
  createdAt: number; // unix ms
  expiresAt: number; // unix ms (local convention: +3y at creation)
}

export interface DepositRecord {
  address: string; // lowercase 0x…
  valueWei: string;
  treeIndex: number;
  /** Server exposes no deposit timestamp — local clock at first observation. */
  firstSeenAt: number;
}

export interface HistoryItem {
  id: string;
  kind: 'withdrawal' | 'card';
  title: string;
  subtitle: string;
  /** Signed: + incoming, − outgoing. */
  amountWei: bigint;
  at: number; // unix ms
}

export interface CardEntry {
  id: string;
  name: string;
  number: string;
  amountWei: string;
  spentWei: string;
  pubkeyX: string;
  /** 3-digit CVC — STUB. Random at creation; legacy cards derive from id. */
  cvc?: string;
  createdAt: number;
  expiresAt: number;
}
