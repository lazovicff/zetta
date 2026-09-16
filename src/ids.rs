
//! Deterministic display handle: CrockfordBase32(keccak256(be32(pubkey_x))[0..8]).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Digest, Keccak256};

const B32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford, no I/L/O/U

/// `XXXX-XXXX-XXXXX` — 64 bits, matches mobile/src/crypto/ids.ts.
pub fn user_id(pubkey_x: Fr) -> String {
    let bytes = pubkey_x.into_bigint().to_bytes_be();
    let h = Keccak256::digest(bytes);
    let mut n = u64::from_be_bytes(h[0..8].try_into().unwrap());
    let mut out = [0u8; 13];
    for c in out.iter_mut().rev() {
        *c = B32[(n & 31) as usize];
        n >>= 5;
    }
    let s = String::from_utf8(out.to_vec()).unwrap();
    format!("{}-{}-{}", &s[0..4], &s[4..8], &s[8..13])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use ark_ec::{CurveGroup, PrimeGroup};

    /// Same key as burn.rs print_mobile_vector — compare the ID against mobile output.
    #[test]
    fn print_user_id_vector() {
        let x = Fq::from(123456789u64);
        let p = (ark_grumpkin::Projective::generator() * x).into_affine();
        println!("PUBKEY_X = {}", p.x);
        println!("USER_ID = {}", user_id(p.x));
    }
}
