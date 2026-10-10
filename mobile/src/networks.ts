/** Deposit network. */
export interface Network {
  id: string;
  name: string;
  enabled: boolean;
  /** EIP-155 chain id, e.g. 8453 for Base mainnet. */
  chainId: number;
}

export const NETWORKS: Network[] = [
  { id: 'base', name: 'Base', enabled: true, chainId: 8453 },
];

/** CAIP-2 network id, e.g. 'eip155:8453', used to match x402 payment options. */
export function caipId(network: Network): string {
  return `eip155:${network.chainId}`;
}
