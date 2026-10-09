import fs from "node:fs";
import path from "node:path";

// USDC is an external token (not in broadcast) — well-known per-chain addresses.
const USDC = {
  84532: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  8453: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
};

const broadcastDir = path.resolve("..", "broadcast", "Deploy.s.sol");
const out = {};

for (const dir of fs.readdirSync(broadcastDir)) {
  const chainId = Number(dir);
  const file = path.join(broadcastDir, dir, "run-latest.json");
  if (!fs.existsSync(file)) continue;
  const { transactions } = JSON.parse(fs.readFileSync(file, "utf8"));
  const addr = (name) => transactions.find((t) => t.contractName === name)?.contractAddress;
  out[chainId] = {
    usdc: USDC[chainId],
    token: addr("zERC20"),
    vault: addr("USDCVault"),
  };
}

fs.writeFileSync(path.resolve("data", "addresses.json"), JSON.stringify(out, null, 2));
console.log("wrote web/data/addresses.json");
