export const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
  "function allowance(address,address) view returns (uint256)",
];

export const VAULT_ABI = [
  "function wrap(uint256)",
  "function unwrap(uint256)",
];

export const DIST_ABI = [
  "function stake(uint256)",
  "function withdraw(uint256)",
  "function getReward()",
  "function exit()",
  "function balanceOf(address) view returns (uint256)",
  "function earned(address) view returns (uint256)",
];
