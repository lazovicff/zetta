import { createConfig } from "@privy-io/wagmi";
import { defineChain, http } from "viem";

export const anvil = defineChain({
  id: 31337,
  name: "Anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: ["http://localhost:8545"] } },
});

export const config = createConfig({
  chains: [anvil],
  transports: { [anvil.id]: http() },
});
