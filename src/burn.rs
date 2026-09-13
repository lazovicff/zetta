use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// `recipient = trim246(keccak256(chain_id_be8 ‖ address_20 ‖ tweak_32))`.
pub fn recipient(chain_id: u64, address: [u8; 20], tweak: [u8; 32]) -> Fr {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(chain_id.to_be_bytes());
    hasher.update(address);
    hasher.update(tweak);
    let mut h: [u8; 32] = hasher.finalize().into();
    h[0] = 0;
    h[1] &= 0x3f;
    Fr::from_be_bytes_mod_order(&h)
}

/// Lower 160 bits of `x` as a 20-byte big-endian address.
pub fn trim_to_160(x: Fr) -> [u8; 20] {
    let bytes = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[12..32]);
    out
}

/// Embed a 20-byte address into Fr (big-endian, zero-padded to 32 bytes).
pub fn address_to_fr(address: [u8; 20]) -> Fr {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(&address);
    Fr::from_be_bytes_mod_order(&b)
}
