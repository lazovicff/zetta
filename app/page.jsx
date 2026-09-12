import { ConnectButton } from "@rainbow-me/rainbowkit";
import { Tabs } from "@/components/Tabs";

export default function Home() {
  return (
    <main className="wrap">
      <div className="header">
        <h1>Zetta DAI</h1>
        <ConnectButton />
      </div>
      <Tabs />
    </main>
  );
}
