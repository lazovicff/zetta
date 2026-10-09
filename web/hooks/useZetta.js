"use client";

import { useQueryClient } from "@tanstack/react-query";
import { readContract, waitForTransactionReceipt } from "@wagmi/core";
import { useAccount, useReadContract, useWriteContract } from "wagmi";
import { parseUnits } from "viem";
import { config } from "@/config/wagmi";
import { getAddresses } from "@/lib/contracts";
import { ERC20_ABI, VAULT_ABI } from "@/lib/abis";

function parseAmount(s) {
  if (!s || Number(s) <= 0) throw new Error("Enter a valid amount");
  return parseUnits(s, 6);
}

export function useBalances() {
  const { address, chainId } = useAccount();
  const A = getAddresses(chainId);
  const usdc = useReadContract({
    address: A.usdc, abi: ERC20_ABI, functionName: "balanceOf",
    args: [address], chainId,
  });
  return { usdc: usdc.data ?? 0n, zusdc: 0n };
}

export function useWrap() {
  const { address, chainId } = useAccount();
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const wrap = async (amountStr) => {
    const A = getAddresses(chainId);
    const amount = parseAmount(amountStr);
    const allowance = await readContract(config, {
      address: A.usdc, abi: ERC20_ABI, functionName: "allowance", args: [address, A.vault],
    });
    if (allowance < amount) {
      const h = await writeContractAsync({ address: A.usdc, abi: ERC20_ABI, functionName: "approve", args: [A.vault, amount] });
      await waitForTransactionReceipt(config, { hash: h });
    }
    const hash = await writeContractAsync({ address: A.vault, abi: VAULT_ABI, functionName: "wrap", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { wrap };
}

export function useUnwrap() {
  const { chainId } = useAccount();
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const unwrap = async (amountStr) => {
    const A = getAddresses(chainId);
    const amount = parseAmount(amountStr);
    const hash = await writeContractAsync({ address: A.vault, abi: VAULT_ABI, functionName: "unwrap", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { unwrap };
}
