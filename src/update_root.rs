use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use folding_schemes::frontend::FCircuit;

use crate::tree::{HashChain, MerkleTree};
use crate::zkp::{RootTransitionCircuit, RootTransitionWitness, prove_root_transition};
use crate::{burn::address_to_fr, zkp::poseidon2};

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
}

sol! {
    #[sol(rpc)]
    interface IZettaToken {
        function burnIndex() external view returns (uint256);
        function burnHashChain() external view returns (uint256);
    }
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function updateRoot(uint256[32] proof) external;
        function transferIndex() external view returns (uint256);
    }
}

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn decode_opaque_proof(calldata: &[u8]) -> [U256; 32] {
    let mut out = [U256::ZERO; 32];
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
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer: PrivateKeySigner = private_key.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(rpc_url.parse()?);

    // Fetch Transfer events (from != 0x0), ordered by (blockNumber, logIndex),
    // from genesis so no burn is missed.
    let filter = Filter::new()
        .address(token)
        .event_signature(Transfer::SIGNATURE_HASH)
        .from_block(0);
    let mut logs = provider.get_logs(&filter).await?;
    logs.sort_by_key(|l| (l.block_number, l.log_index));

    let mut tree = MerkleTree::new(32);
    let mut chain = HashChain::new();
    let mut witnesses = Vec::new();
    for log in &logs {
        let decoded = log.log_decode::<Transfer>()?;
        let d = decoded.data();
        if d.from.is_zero() {
            continue; // mint — excluded from tree
        }
        let to_bytes: [u8; 20] = d.to.into_array();
        let value_fr = u256_to_fr(d.value);

        let index = tree.len();
        let proof = tree.proof_for_empty(index);
        let mut merkle_path = [Fr::zero(); 32];
        merkle_path.copy_from_slice(&proof);
        witnesses.push(RootTransitionWitness {
            to: address_to_fr(to_bytes),
            value: value_fr,
            merkle_path,
        });

        let leaf = poseidon2(address_to_fr(to_bytes), value_fr)?;
        tree.insert(leaf);
        chain.apply(to_bytes, value_fr);
    }

    // Empty code at --token = the broadcast is from a previous anvil session.
    if provider.get_code_at(token).await?.is_empty() {
        return Err(format!(
            "no contract at --token {token} on this node; deployment is stale — run scripts/deploy.sh"
        )
        .into());
    }

    // Fail fast before the (expensive) decider proof: updateRoot checks the proof's
    // final (index, hashChain) against the token the Verifier was deployed with.
    // A wrong or stale --token address otherwise surfaces only after minutes of
    // proving, as an opaque on-chain "index mismatch" revert.
    let token_contract = IZettaToken::new(token, provider.clone());
    let on_chain_index = token_contract.burnIndex().call().await?;
    let on_chain_chain = token_contract.burnHashChain().call().await?;
    let local_index = U256::from(tree.len() as u64);
    let local_chain = U256::from_be_slice(&chain.state().into_bigint().to_bytes_be());
    if local_index != on_chain_index || local_chain != on_chain_chain {
        return Err(format!(
            "replayed events do not match on-chain token state \
             (index {local_index} vs {on_chain_index}, hashChain {local_chain} vs {on_chain_chain}); \
             pass the --token the burns were sent to, from the same deployment as --verifier"
        )
        .into());
    }

    let contract = IVerifier::new(verifier, provider);
    let stored_index = contract.transferIndex().call().await?;
    if !stored_index.is_zero() {
        return Err(format!(
            "verifier root already advanced to index {stored_index}; \
             this CLI proves from genesis only — redeploy to reset"
        )
        .into());
    }

    let initial_root = MerkleTree::new(32).root();
    let z_0 = vec![Fr::zero(), Fr::zero(), initial_root];

    let circuit = RootTransitionCircuit::new(())?;
    let (calldata, _solidity_code) = prove_root_transition(circuit, z_0, witnesses)?;

    let proof_arr = decode_opaque_proof(&calldata);

    let tx = contract.updateRoot(proof_arr).send().await?;
    let receipt = tx.get_receipt().await?;

    println!("tx hash = {}", receipt.transaction_hash);
    Ok(())
}
