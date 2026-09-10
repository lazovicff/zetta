//! Burn-address cryptography + `burn` command (zERC20-style private ERC-20).

use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 value) external returns (bool);
    }
}

/// Generate `count` PoW-valid secrets (and their burn addresses) for `recipient`.
pub fn gen_secrets(recipient: Fr, count: usize, pow_bits: u32) -> Vec<([u8; 20], Fr)> {
    (0..count)
        .map(|_| find_burn_address(recipient, pow_bits))
        .collect()
}

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

/// PoW check: bits `[160, 160+n)` of `x` are zero.
pub fn check_pow(x: Fr, n: u32) -> bool {
    let bytes = x.into_bigint().to_bytes_be();
    for p in 160..(160 + n) {
        let byte = 31 - (p / 8) as usize;
        let bit = (p % 8) as u8;
        if (bytes[byte] >> bit) & 1 == 1 {
            return false;
        }
    }
    true
}

/// Random secret; returns `(burn_address, secret)` satisfying `check_pow(_, n)`.
pub fn find_burn_address(recipient: Fr, pow_bits: u32) -> ([u8; 20], Fr) {
    use ark_std::UniformRand;
    let mut rng = rand::thread_rng();
    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("poseidon");
    loop {
        let secret = Fr::rand(&mut rng);
        let h = poseidon.hash(&[recipient, secret]).expect("poseidon");
        if check_pow(h, pow_bits) {
            return (trim_to_160(h), secret);
        }
    }
}

/// `zetta burn`: derive a burn address and send a plain transfer to it.
pub async fn run(
    rpc_url: &str,
    token: Address,
    recipient_addr: Address,
    tweak: B256,
    amount: U256,
    pow_bits: u32,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url.parse()?);

    let chain_id = provider.get_chain_id().await?;

    let recipient = recipient(chain_id, recipient_addr.into_array(), tweak.0);
    let (burn_address, secret) = find_burn_address(recipient, pow_bits);

    let contract = IERC20::new(token, provider);
    let tx = contract
        .transfer(Address::from(burn_address), amount)
        .send()
        .await?;
    let receipt = tx.get_receipt().await?;

    println!("burn address = 0x{}", hex::encode(burn_address));
    println!("secret       = {}", secret);
    println!("tx hash      = {}", receipt.transaction_hash);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::zkp::poseidon2;
    use ark_ff::{BigInteger, Field, Zero};

    use super::*;

    fn fr_from_hex(hex: &str) -> Fr {
        let bytes = hex::decode(hex).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        Fr::from_be_bytes_mod_order(&b)
    }

    #[test]
    fn poseidon_known_vector() {
        let h = poseidon2(Fr::from(1u64), Fr::from(2u64)).unwrap();
        let expected =
            fr_from_hex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
        assert_eq!(h, expected);
    }

    #[test]
    fn recipient_deterministic_and_in_range() {
        let a = [0x11u8; 20];
        let t = [0x22u8; 32];
        let r1 = recipient(31337, a, t);
        assert_eq!(r1, recipient(31337, a, t));
        let bytes = r1.into_bigint().to_bytes_be();
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1] & 0xc0, 0);
        let mut t2 = t;
        t2[0] ^= 1;
        assert_ne!(r1, recipient(31337, a, t2));
    }

    #[test]
    fn trim_keeps_lower_160_bits() {
        let x = Fr::from(0x1234u64);
        let addr = trim_to_160(x);
        assert_eq!(addr[18], 0x12);
        assert_eq!(addr[19], 0x34);
        assert!(addr[..18].iter().all(|&b| b == 0));
    }

    #[test]
    fn check_pow_edge_cases() {
        let two = Fr::from(2u64);
        assert!(check_pow(two.pow([160u64]), 0));
        assert!(check_pow(two.pow([159u64]), 20));
        assert!(!check_pow(two.pow([160u64]), 1));
        assert!(check_pow(two.pow([161u64]), 1));
        assert!(!check_pow(two.pow([161u64]), 2));
        assert!(check_pow(Fr::zero(), 20));
    }

    #[test]
    fn find_burn_address_satisfies_pow() {
        let r = recipient(1, [0x33u8; 20], [0x44u8; 32]);
        let (addr, secret) = find_burn_address(r, 8);
        let h = poseidon2(r, secret).unwrap();
        assert!(check_pow(h, 8));
        assert_eq!(trim_to_160(h), addr);
    }
}
