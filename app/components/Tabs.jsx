"use client";

import { useState } from "react";
import { WrapUnwrap } from "@/components/WrapUnwrap";
import { StakeUnstake } from "@/components/StakeUnstake";
import { Rewards } from "@/components/Rewards";

const TABS = [
  { id: "wrap", label: "Wrap / Unwrap" },
  { id: "stake", label: "Stake / Unstake" },
  { id: "rewards", label: "Rewards" },
];

export function Tabs() {
  const [active, setActive] = useState("wrap");

  return (
    <div className="card">
      <div className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={active === tab.id ? "tab active" : "tab"}
            onClick={() => setActive(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {active === "wrap" && <WrapUnwrap />}
      {active === "stake" && <StakeUnstake />}
      {active === "rewards" && <Rewards />}
    </div>
  );
}
