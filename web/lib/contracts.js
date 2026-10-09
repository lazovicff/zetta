import addresses from "@/data/addresses.json";

export function getAddresses(chainId) {
  const a = addresses[chainId];
  return {
    usdc: a?.usdc ?? "0x",
    token: a?.token ?? "0x",
    vault: a?.vault ?? "0x",
  };
}
