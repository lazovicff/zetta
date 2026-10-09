import { parseAbi } from "viem";

export const ERC20_ABI = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function allowance(address,address) view returns (uint256)",
]);

export const VAULT_ABI = parseAbi([
  "function wrap(uint256)",
  "function unwrap(uint256)",
]);
