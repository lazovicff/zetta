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
  return parseEther(s);
}

export function useBalances() {
  const { address } = useAccount();
  const dai = useReadContract({ address: ADDRESSES.dai, abi: ERC20_ABI, functionName: "balanceOf", args: [address] });
  const zdai = useReadContract({ address: ADDRESSES.token, abi: ERC20_ABI, functionName: "balanceOf", args: [address] });
  const staked = useReadContract({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "balanceOf", args: [address] });
  const rewards = useReadContract({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "earned", args: [address] });
  return {
    dai: dai.data ?? 0n,
    zdai: zdai.data ?? 0n,
    staked: staked.data ?? 0n,
    rewards: rewards.data ?? 0n,
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

export function useStake() {
  const { address } = useAccount();
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const stake = async (amountStr) => {
    const amount = parseAmount(amountStr);
    const allowance = await readContract(config, {
      address: ADDRESSES.token, abi: ERC20_ABI, functionName: "allowance", args: [address, ADDRESSES.dist],
    });
    if (allowance < amount) {
      const h = await writeContractAsync({ address: ADDRESSES.token, abi: ERC20_ABI, functionName: "approve", args: [ADDRESSES.dist, amount] });
      await waitForTransactionReceipt(config, { hash: h });
    }
    const hash = await writeContractAsync({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "stake", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { stake };
}

export function useUnstake() {
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const unstake = async (amountStr) => {
    const amount = parseAmount(amountStr);
    const hash = await writeContractAsync({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "withdraw", args: [amount] });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { unstake };
}

export function useClaim() {
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const claim = async () => {
    const hash = await writeContractAsync({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "getReward" });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { claim };
}

export function useExit() {
  const { writeContractAsync } = useWriteContract();
  const queryClient = useQueryClient();

  const exit = async () => {
    const hash = await writeContractAsync({ address: ADDRESSES.dist, abi: DIST_ABI, functionName: "exit" });
    await waitForTransactionReceipt(config, { hash });
    queryClient.invalidateQueries();
  };

  return { exit };
}
