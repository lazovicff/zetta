// Burn address derivation, matching src/burn.rs and the withdraw circuit:
//   burn = poseidon2(recipient, P.x)   (over bn254 r == grumpkin coordinate field)
//   address = low 160 bits of burn     (trim_to_160)

import { poseidon2 } from 'poseidon-lite';

/** Poseidon hash binding the recipient epoch to the pubkey (raw field element). */
export function burnHash(recipient: bigint, pubkeyX: bigint): bigint {
  return poseidon2([recipient, pubkeyX]);
}

/** burn address = trim160(poseidon2(recipient, P.x)), 0x-prefixed hex. */
export function burnAddress(recipient: bigint, pubkeyX: bigint): `0x${string}` {
  const h = burnHash(recipient, pubkeyX);
  // 32-byte big-endian, then take the low 20 bytes (== bytes[12..32] in trim_to_160).
  return `0x${h.toString(16).padStart(64, '0').slice(24)}`;
}
