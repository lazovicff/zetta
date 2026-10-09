import { createConfig } from "@privy-io/wagmi";
import { http } from "viem";
import { CHAINS } from "@/lib/chains";

const transports = {
  84532: http("https://sepolia.base.org"),
  8453: http("https://mainnet.base.org"),
};

export const config = createConfig({
  chains: CHAINS,
  transports,
});
