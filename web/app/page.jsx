import { ConnectButton } from "@/components/ConnectButton";
import { Tabs } from "@/components/Tabs";

export default function Home() {
  return (
    <main className="wrap">
      <div className="header">
        <h1>Zetta USDC</h1>
        <ConnectButton />
      </div>
      <Tabs />
    </main>
  );
}
