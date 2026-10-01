"use client";

import { useQueryClient } from "@tanstack/react-query";
import { readContract, waitForTransactionReceipt } from "@wagmi/core";
import { useAccount, useReadContract, useWriteContract } from "wagmi";
import { parseEther } from "viem";
import { config } from "@/config/wagmi";
import { ADDRESSES } from "@/lib/contracts";
import { DIST_ABI, ERC20_ABI, VAULT_ABI } from "@/lib/abis";

function parseAmount(s) {
  if (!s || Number(s) <= 0) throw new Error("Enter a valid amount");
  return parseUnits(s, 6);
}

export function useBalances() {
  const { address } = useAccount();
  const usdc = useReadContract({ address: ADDRESSES.usdc, abi: ERC20_ABI, functionName: "balanceOf", args: [address] });
  const zusdc = useReadContract({ address: ADDRESSES.token, abi: ERC20_ABI, functionName: "balanceOf", args: [address] });
  return {
    usdc: usdc.data ?? 0n,
    zusdc: zusdc.data ?? 0n,
  };
}

export function useWrap() {
  const { address } = useAccount();
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const wrap = async (amountStr) => {
    const amount = parseAmount(amountStr);
    const allowance = await readContract(config, {
      address: ADDRESSES.dai, abi: ERC20_ABI, functionName: "allowance", args: [address, ADDRESSES.vault],
    });
    if (allowance < amount) {
      const h = await writeContractAsync({ address: ADDRESSES.dai, abi: ERC20_ABI, functionName: "approve", args: [ADDRESSES.vault, amount] });
      await waitForTransactionReceipt(config, { hash: h });
    }
    const hash = await writeContractAsync({ address: ADDRESSES.vault, abi: VAULT_ABI, functionName: "wrap", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { wrap };
}

export function useUnwrap() {
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const unwrap = async (amountStr) => {
    const amount = parseAmount(amountStr);
    const hash = await writeContractAsync({ address: ADDRESSES.vault, abi: VAULT_ABI, functionName: "unwrap", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { unwrap };
}
