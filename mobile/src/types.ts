export interface BurnEntry {
  /** 0x + 40 hex chars — the burn address shown in the list. */
  address: string;
  /** x-coordinate of the pubkey, decimal (grumpkin Fq). */
  pubkeyX: string;
  /** Recipient epoch this address was derived under, decimal (bn254 Fr). */
  recipient: string;
  /** Unix ms. */
  createdAt: number;
}
