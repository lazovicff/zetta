"use client";

import { usePrivy } from "@privy-io/react-auth";
import { useAccount } from "wagmi";

export function ConnectButton() {
  const { ready, authenticated, login, logout } = usePrivy();
  const { address } = useAccount();
  if (!ready) return <button disabled>Loading…</button>;
  if (!authenticated) return <button onClick={login}>Connect</button>;
  return (
    <button onClick={logout}>
      {address ? `${address.slice(0, 6)}…${address.slice(-4)}` : "Disconnect"}
    </button>
  );
}
