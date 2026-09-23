export interface HistoryItem {
  id: string;
  kind: 'deposit' | 'card' | 'withdraw';
  title: string;
  subtitle: string;
  /** Signed: + incoming, − outgoing. */
  amountWei: bigint;
  at: number; // unix ms
}
