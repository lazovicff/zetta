// Burn address derivation, matching src/server.rs and the withdraw circuit:
//   burn = poseidon3(recipient, P.x, salt)   (over bn254 r == grumpkin coordinate field)
//   address = low 160 bits of burn           (trim_to_160)
//
// salt is a public nonce: vary it to mint fresh burn addresses for one keypair.

import { poseidon3 } from 'poseidon-lite';

/** Poseidon hash binding (recipient epoch, pubkey, salt). Raw field element. */
export function burnHash(recipient: bigint, pubkeyX: bigint, salt: bigint): bigint {
  return poseidon3([recipient, pubkeyX, salt]);
}

/** burn address = trim160(poseidon3(recipient, P.x, salt)), 0x-prefixed hex. */
export function burnAddress(
  recipient: bigint,
  pubkeyX: bigint,
  salt: bigint,
): `0x${string}` {
  const h = burnHash(recipient, pubkeyX, salt);
  // 32-byte big-endian, then take the low 20 bytes (== bytes[12..32] in trim_to_160).
  return `0x${h.toString(16).padStart(64, '0').slice(24)}`;
}
