"use client";

import { useEffect, useState } from "react";
import { useAccount } from "wagmi";
import { formatEther } from "viem";
import { useClaim, useExit, useBalances } from "@/hooks/useZetta";

export function Rewards() {
  const { isConnected } = useAccount();
  const { claim } = useClaim();
  const { exit } = useExit();
  const b = useBalances();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted || !isConnected) return null;

  const run = async (fn) => {
    setBusy(true);
    setError("");
    try { await fn(); } catch (e) { setError(e.shortMessage ?? e.message); }
    setBusy(false);
  };

  return (
    <div className="swap">
      <div className="field">
        <div className="field-label">Available rewards</div>
        <div className="field-row">
          <span className="value">{formatEther(b.rewards)}</span>
          <span className="token">DAI</span>
        </div>
      </div>

      <button className="submit" disabled={busy} onClick={() => run(claim)}>Claim</button>
      <button className="submit ghost" disabled={busy} onClick={() => run(exit)}>Exit (unstake + claim)</button>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
