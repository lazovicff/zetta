import { defineChain } from "viem";

export const CHAINS = [
  defineChain({
    id: 84532,
    name: "Base Sepolia",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: ["https://sepolia.base.org"] } },
  }),
  defineChain({
    id: 8453,
    name: "Base",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: ["https://mainnet.base.org"] } },
  }),
];
