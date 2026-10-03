/** Deposit network. */
export interface Network {
  id: string;
  name: string;
  enabled: boolean;
}

export const NETWORKS: Network[] = [
  { id: 'base', name: 'Base', enabled: true },
];
