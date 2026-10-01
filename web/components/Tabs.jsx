"use client";

import { useState } from "react";
import { WrapUnwrap } from "@/components/WrapUnwrap";

const TABS = [
  { id: "wrap", label: "Wrap / Unwrap" },
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
    </div>
  );
}
