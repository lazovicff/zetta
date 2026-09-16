// Deterministic handle for the identity pubkey:
//   id = CrockfordBase32(keccak256(be32(pubkey_x))[0..8])   (64 bits)

import { keccak_256 } from '@noble/hashes/sha3.js';

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford, no I/L/O/U

export function userId(pubkeyX: bigint): string {
  const bytes = new Uint8Array(32);
  let v = pubkeyX;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const h = keccak_256(bytes).slice(0, 8);
  let n = 0n;
  for (const b of h) n = (n << 8n) | BigInt(b);
  let out = '';
  for (let i = 0; i < 13; i++) {
    out = B32[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return `${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8)}`;
}
