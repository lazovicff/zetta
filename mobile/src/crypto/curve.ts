// Grumpkin curve on the bn254 cycle, matching ark-grumpkin exactly
// (arkworks-rs/algebra @ c1f4f56, curves/grumpkin/src/curves/mod.rs):
//
//   y² = x³ − 17                      over Fq (coords),  Fq q = bn254 scalar field r
//   group order n = bn254 base field q, cofactor 1       Fr (scalars), Fr p = bn254 base field
//   G = (1, 17631683881184975370165255887551781615748388533673675138860)
//
// Naming follows ark-grumpkin: Fq = coordinate/base field, Fr = scalar field.
// Note: e < r implies e < q, so the circuit (Fr bits) and this code (Fq scalars)
// interpret the challenge identically, as in src/zkp/withdraw.rs.

import { Field } from '@noble/curves/abstract/modular';
import { weierstrass } from '@noble/curves/abstract/weierstrass';
import { sha256 } from '@noble/hashes/sha2.js';
import { poseidon2, poseidon3 } from 'poseidon-lite';

const CARD_ORDER_DOMAIN = 0x63617264n; // "card" — matches CARD_ORDER_DOMAIN in src/server/db.rs
/** Coordinate field modulus (== bn254 scalar field r). */
export const FQ_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Scalar field modulus == group order (== bn254 base field q). */
export const FR_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export const Fq = Field(FQ_MODULUS);
export const Fr = Field(FR_MODULUS);

const grumpkin = weierstrass({
  a: 0n,
  b: FQ_MODULUS - 17n, // COEFF_B = −17
  Fp: Fq,
  n: FR_MODULUS,
  Gx: 1n, // G_GENERATOR_X
  Gy: 17631683881184975370165255887551781615748388533673675138860n, // G_GENERATOR_Y
  h: 1n, // COFACTOR
  hash: sha256, // unused by us (no ECDSA); the constructor requires a wrapped hash
});

const Point = grumpkin.ProjectivePoint;
export type ProjPoint = InstanceType<typeof Point>;

export interface AffinePoint {
  x: bigint;
  y: bigint;
}

export interface SchnorrSig {
  /** R = k·G, affine. */
  sigR: AffinePoint;
  /** z = k + e·x (mod Fr). */
  sigZ: bigint;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function toAffine(p: ProjPoint): AffinePoint {
  const { x, y } = p.toAffine();
  return { x, y };
}

/** Uniformly random secret scalar x ∈ [1, n). Rejection sampling — no modulo bias. */
export function randomScalar(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf); // polyfilled in index.ts (RN); native in Node/vitest
    const x = bytesToBigIntBE(buf);
    if (x >= 1n && x < FR_MODULUS) return x;
  }
}

/** Uniformly random salt ∈ [0, Fq) for burn-address derivation. Not secret. */
export function randomSalt(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf);
    const x = bytesToBigIntBE(buf);
    if (x < FQ_MODULUS) return x;
  }
}


/** P = x·G (affine). Throws if x ∉ [1, n). */
export function pubkey(secret: bigint): AffinePoint {
  if (secret <= 0n || secret >= FR_MODULUS) throw new Error('secret out of range');
  return toAffine(Point.BASE.multiply(secret));
}

/**
 * Schnorr signature over grumpkin, matching the circuit:
 *   R = k·G
 *   e = poseidon3(R.x, P.x, recipient)   // poseidon-lite is over bn254 r == grumpkin Fq
 *   z = k + e·x (mod Fr)
 */
export function schnorrSign(secret: bigint, recipient: bigint): SchnorrSig {
  const P = pubkey(secret);
  const k = randomScalar();
  const R = toAffine(Point.BASE.multiply(k));
  const e = poseidon3([R.x, P.x, recipient]);
  const sigZ = Fr.add(k, Fr.mul(e % FR_MODULUS, secret));
  return { sigR: R, sigZ };
}

export function schnorrVerify(
  pub: AffinePoint,
  sig: SchnorrSig,
  recipient: bigint,
): boolean {
  const P = Point.fromAffine(pub);
  const R = Point.fromAffine(sig.sigR);
  const e = poseidon3([sig.sigR.x, pub.x, recipient]);
  return Point.BASE.multiply(sig.sigZ % FR_MODULUS).equals(R.add(P.multiply(e)));
}


/**
 * Card-order auth, matching try_card_order in src/server/db.rs:
 *   msg = poseidon3(CARD_ORDER_DOMAIN, amount, nonce)
 *   e   = poseidon3(R.x, P.x, msg)
 *   z = k + e·x (mod Fr)
 */
export function schnorrSignOrder(secret: bigint, amount: bigint, nonce: bigint): SchnorrSig {
  const P = pubkey(secret);
  const k = randomScalar();
  const R = toAffine(Point.BASE.multiply(k));
  const msg = poseidon3([CARD_ORDER_DOMAIN, amount, nonce]);
  const e = poseidon3([R.x, P.x, msg]);
  const sigZ = Fr.add(k, Fr.mul(e % FR_MODULUS, secret));
  return { sigR: R, sigZ };
}
