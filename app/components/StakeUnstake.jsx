"use client";

import { useEffect, useState } from "react";
import { useAccount } from "wagmi";
import { formatEther } from "viem";
import { useStake, useUnstake, useBalances } from "@/hooks/useZetta";

export function StakeUnstake() {
  const { isConnected } = useAccount();
  const { stake } = useStake();
  const { unstake } = useUnstake();
  const b = useBalances();
  const [amount, setAmount] = useState("");
  const [flipped, setFlipped] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted || !isConnected) return null;

  const payToken = flipped ? "Staked zDAI" : "zDAI";
  const receiveToken = flipped ? "zDAI" : "Staked zDAI";
  const payBalance = flipped ? b.staked : b.zdai;
  const receiveBalance = flipped ? b.zdai : b.staked;

  const run = async (fn) => {
    setBusy(true);
    setError("");
    try { await fn(); } catch (e) { setError(e.shortMessage ?? e.message); }
    setBusy(false);
  };

  const submit = () => (flipped ? run(() => unstake(amount)) : run(() => stake(amount)));

  return (
    <div className="swap">
      <div className="field">
        <div className="field-label">You pay</div>
        <div className="field-row">
          <input type="number" placeholder="0" value={amount} onChange={(e) => setAmount(e.target.value)} />
          <span className="token">{payToken}</span>
        </div>
        <div className="balance-row">
          <span className="balance">Balance: {formatEther(payBalance)}</span>
          <button className="max" onClick={() => setAmount(formatEther(payBalance))}>Max</button>
        </div>
      </div>

      <div className="flip-wrap">
        <button className="flip" onClick={() => setFlipped(!flipped)}>↑↓</button>
      </div>

      <div className="field">
        <div className="field-label">You receive</div>
        <div className="field-row">
          <input type="number" placeholder="0" value={amount} readOnly />
          <span className="token">{receiveToken}</span>
        </div>
        <div className="balance-row">
          <span className="balance">Balance: {formatEther(receiveBalance)}</span>
        </div>
      </div>

      <button className="submit" disabled={busy} onClick={submit}>
        {flipped ? "Unstake" : "Stake"}
      </button>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
