import { describe, expect, it } from 'vitest';
import { poseidon2 } from 'poseidon-lite';

import { burnAddress } from './burn';
import {
  FQ_MODULUS,
  FR_MODULUS,
  pubkey,
  randomScalar,
  schnorrSign,
  schnorrVerify,
} from './curve';

describe('grumpkin params', () => {
  it('generator is on curve: y² = 1³ − 17 (mod Fq)', () => {
    const gy = 17631683881184975370165255887551781615748388533673675138860n;
    const lhs = (gy * gy) % FQ_MODULUS;
    const rhs = (1n - 17n + FQ_MODULUS) % FQ_MODULUS;
    expect(lhs).toBe(rhs);
  });
});

describe('keys + schnorr', () => {
  it('keygen → sign → verify roundtrip', () => {
    const x = randomScalar();
    const P = pubkey(x);
    const recipient = 123456789n;
    const sig = schnorrSign(x, recipient);

    expect(schnorrVerify(P, sig, recipient)).toBe(true);
    // wrong recipient epoch -> invalid (binds signature to the server's current tweak)
    expect(schnorrVerify(P, sig, recipient + 1n)).toBe(false);
  });

  it('is 0x + 40 hex chars', () => {
    expect(burnAddress(1n, 1n, 1n)).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('rejects out-of-range secrets', () => {
    expect(() => pubkey(0n)).toThrow();
    expect(() => pubkey(FR_MODULUS)).toThrow();
  });
});

describe('poseidon compat', () => {
  // PLAN.md Phase A known-vector test; must pass or nothing is compatible.
  it('poseidon2(1, 2) matches circomlib/light-poseidon', () => {
    expect(poseidon2([1n, 2n])).toBe(
      7853200120776062878684798364095072458815029376092732009249414926327459813530n,
    );
  });
});

describe('burnAddress', () => {
  it('is 0x + 40 hex chars', () => {
    expect(burnAddress(1n, 1n, 1n)).toMatch(/^0x[0-9a-f]{40}$/);
  });
});
