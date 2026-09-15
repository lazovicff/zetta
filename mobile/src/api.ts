// Server endpoints (src/server.rs). URL comes from .env (EXPO_PUBLIC_*).

const SERVER_URL = process.env.EXPO_PUBLIC_SERVER_URL;

/** Current recipient epoch: trim246(keccak(chain_id ‖ exchange_addr ‖ tweak)). */
export async function getRecipient(): Promise<bigint> {
  if (!SERVER_URL) {
    throw new Error('EXPO_PUBLIC_SERVER_URL is not set — check mobile/.env');
  }
  const res = await fetch(`${SERVER_URL}/recipient`);
  if (!res.ok) throw new Error(`GET /recipient failed: ${res.status}`);
  const { recipient } = (await res.json()) as { recipient: string };
  return BigInt(recipient);
}
