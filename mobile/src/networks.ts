/** Deposit networks. Only `enabled` networks can be picked; the rest render greyed out. */
export interface Network {
  id: string;
  name: string;
  enabled: boolean;
}

export const NETWORKS: Network[] = [
  { id: 'ethereum', name: 'Ethereum', enabled: true },
  { id: 'base', name: 'Base', enabled: false },
  { id: 'arbitrum', name: 'Arbitrum', enabled: false },
];
