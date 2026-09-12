use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use folding_schemes::frontend::FCircuit;

use crate::tree::{MerkleTree, TREE_DEPTH};
use crate::zkp::{WithdrawCircuit, WithdrawParams, WithdrawWitness, prove_withdraw};
use crate::{
    burn::{address_to_fr, recipient, trim_to_160},
    zkp::poseidon2,
};

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] proof) external;
    }
}

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn parse_fr_decimal(s: &str) -> Result<Fr, Box<dyn std::error::Error>> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).ok_or("invalid decimal")?;
    Ok(Fr::from_be_bytes_mod_order(&n.to_bytes_be()))
}

/// Decode Opaque-mode calldata (4-byte selector + 34 uint256) into a fixed array.
fn decode_opaque_proof(calldata: &[u8]) -> [U256; 34] {
    let mut out = [U256::ZERO; 34];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = 4 + i * 32;
        let mut b = [0u8; 32];
        b.copy_from_slice(&calldata[start..start + 32]);
        *slot = U256::from_be_bytes(b);
    }
    out
}

pub async fn run(
    rpc_url: &str,
    token: Address,
    verifier: Address,
    recipient_addr: Address,
    tweak: B256,
    secrets: &str,
    values: &str,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url.parse()?);
    let chain_id = provider.get_chain_id().await?;

    // Parse the receipt lists.
    let secrets: Vec<&str> = secrets
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let values: Vec<U256> = values
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<U256>())
        .collect::<Result<Vec<_>, _>>()?;
    if secrets.len() != values.len() {
        return Err(
            "--secret and --value must have the same number of comma-separated entries".into(),
        );
    }
    // The generated on-chain decider reverts on Nova instances that folded < 2 steps.
    if secrets.len() < 2 {
        return Err("the on-chain decider requires at least 2 folded receipts; \
                    pass at least 2 --secret/--value pairs"
            .into());
    }

    let recipient = recipient(chain_id, recipient_addr.into_array(), tweak.0);

    // Burn address + leaf per receipt.
    let mut receipts = Vec::with_capacity(secrets.len());
    for (&s, &v) in secrets.iter().zip(&values) {
        let secret_fr = parse_fr_decimal(s)?;
        let burn = poseidon2(recipient, secret_fr)?;
        let burn_addr = trim_to_160(burn);
        let value_fr = u256_to_fr(v);
        let leaf = poseidon2(address_to_fr(burn_addr), value_fr)?;
        receipts.push((secret_fr, value_fr, leaf, None::<usize>));
    }

    // Reconstruct the transfer tree from on-chain Transfer events.
    let filter = Filter::new()
        .address(token)
        .event_signature(Transfer::SIGNATURE_HASH)
        .from_block(0);
    let logs = provider.get_logs(&filter).await?;

    let mut tree = MerkleTree::new(32);
    for log in &logs {
        let decoded = log.log_decode::<Transfer>()?;
        let d = decoded.data();
        if d.from.is_zero() || d.to.is_zero() {
            continue;
        }
        let to_bytes: [u8; 20] = d.to.into_array();
        let l = poseidon2(address_to_fr(to_bytes), u256_to_fr(d.value))?;
        let index = tree.len();
        tree.insert(l);
        for r in &mut receipts {
            if r.3.is_none() && r.2 == l {
                r.3 = Some(index);
            }
        }
    }

    // Witnesses in strictly increasing tree-index order (circuit requirement).
    let mut by_index = Vec::with_capacity(receipts.len());
    for (secret, value, _leaf, idx) in receipts {
        let idx = idx.ok_or("burn leaf not found in tree — check --token/--secret/--value")?;
        by_index.push((idx, secret, value));
    }
    by_index.sort_by_key(|&(idx, _, _)| idx);

    let transfer_root = tree.root();
    let mut witnesses = Vec::with_capacity(by_index.len());
    for (idx, secret, value) in by_index {
        let proof = tree.proof(idx);
        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        witnesses.push(WithdrawWitness {
            secret,
            value,
            index: Fr::from(idx as u64),
            merkle_path,
        });
    }

    let z_0 = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];
    let circuit = WithdrawCircuit::new(WithdrawParams { pow_bits: 20 })?;
    let calldata = prove_withdraw(circuit, z_0, witnesses)?;

    let proof_arr = decode_opaque_proof(&calldata);

    let contract = IVerifier::new(verifier, provider);
    let tx = contract
        .withdraw(U256::from(chain_id), recipient_addr, tweak, proof_arr)
        .send()
        .await?;
    let receipt = tx.get_receipt().await?;

    println!("tx hash = {}", receipt.transaction_hash);
    Ok(())
}
