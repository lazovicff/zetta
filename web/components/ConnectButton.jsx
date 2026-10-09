"use client";

import { useEffect, useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import { useAccount, useDisconnect, useSwitchChain } from "wagmi";
import { CHAINS } from "@/lib/chains";

export function ConnectButton() {
  const { ready, authenticated, login, logout } = usePrivy();
  const { address, chainId } = useAccount();
  const { switchChain } = useSwitchChain();
  const { disconnect } = useDisconnect();
  const [open, setOpen] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted || !ready) {
    return <button className="connect-btn" disabled>Loading…</button>;
  }

  // Not connected: plain Connect button, no dropdown.
  if (!authenticated) {
    return <button className="connect-btn" onClick={login}>Connect</button>;
  }

  const chain = CHAINS.find((c) => c.id === chainId);

  return (
    <div className="connect-menu">
      <button className="connect-btn" onClick={() => setOpen((v) => !v)}>
        <span>{chain?.name ?? "Unknown network"}</span>
        <span>{address ? `${address.slice(0, 6)}…${address.slice(-4)}` : "▾"}</span>
      </button>
      {open && (
        <div className="connect-dropdown">
          {CHAINS.map((c) => (
            <button
              key={c.id}
              className={c.id === chainId ? "connect-item active" : "connect-item"}
              onClick={() => { switchChain({ chainId: c.id }); setOpen(false); }}
            >
              <span>{c.name}</span>
              {c.id === chainId && <span>✓</span>}
            </button>
          ))}
          <hr className="connect-sep" />
          <button
            className="connect-item danger"
            onClick={() => { disconnect(); logout(); setOpen(false); }}
          >
            Disconnect
          </button>
        </div>
      )}
    </div>
  );
}
