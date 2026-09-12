use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolEvent;
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use axum::extract::State as AxumState;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use folding_schemes::frontend::FCircuit;

use crate::burn::{address_to_fr, recipient};
use crate::config::Config;
use crate::state::State;
use crate::tree::{MerkleTree, TREE_CAPACITY, TREE_DEPTH};
use crate::zkp::poseidon2;
use crate::zkp::{
    RootTransitionCircuit, RootTransitionWitness, WithdrawCircuit, WithdrawParams, WithdrawWitness,
    prove_root_transition, prove_withdraw,
};

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function updateRoot(uint256[32] proof) external;
        function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256 rootIndex, uint256[34] proof) external;
        function transferIndex() external view returns (uint256);
        function transferRootsLength() external view returns (uint256);
        function transferRoots(uint256 index) external view returns (uint256);
    }

}

type SharedState = Arc<Mutex<State>>;

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn decode_opaque_proof<const N: usize>(calldata: &[u8]) -> [U256; N] {
    let mut out = [U256::ZERO; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = 4 + i * 32;
        let mut b = [0u8; 32];
        b.copy_from_slice(&calldata[start..start + 32]);
        *slot = U256::from_be_bytes(b);
    }
    out
}

async fn fetch_transfers(
    provider: &impl Provider,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<([u8; 20], Fr)>, Box<dyn std::error::Error>> {
    let filter = Filter::new()
        .address(token)
        .event_signature(Transfer::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(to_block);
    let mut logs = provider.get_logs(&filter).await?;
    logs.sort_by_key(|l| (l.block_number, l.log_index));
    let mut transfers = Vec::new();
    for log in &logs {
        let decoded = log.log_decode::<Transfer>()?;
        let d = decoded.data();
        if d.from.is_zero() || d.to.is_zero() {
            continue;
        }
        transfers.push((d.to.into_array(), u256_to_fr(d.value)));
    }
    Ok(transfers)
}

fn apply_transfer(
    s: &mut State,
    to: [u8; 20],
    value: Fr,
    build_witness: bool,
) -> Result<Option<RootTransitionWitness>, Box<dyn std::error::Error>> {
    let to_fr = address_to_fr(to);
    let index = s.tree.len();
    let witness = if build_witness {
        let proof = s.tree.proof_for_empty(index);
        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        Some(RootTransitionWitness {
            to: to_fr,
            value,
            merkle_path,
        })
    } else {
        None
    };
    let leaf = poseidon2(to_fr, value)?;
    s.tree.insert(leaf);
    s.chain.apply(to, value);
    if s.secret_by_addr.contains_key(&to) {
        let root_index = s.finalized_trees.len();
        s.deposits.insert(to, (value, root_index, index));
    }
    Ok(witness)
}

fn log_burn_addresses(state: &SharedState) {
    let s = state.lock().unwrap();
    for (i, addr) in s.burn_addresses.iter().enumerate() {
        println!("burn address #{} = 0x{}", i, hex::encode(addr));
    }
}

fn spawn_http_server(state: SharedState, port: u16) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(health))
            .route("/deposit-address", get(deposit_address))
            .route("/deposits", get(deposits))
            .route("/status", get(status))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
    });
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;

    let signer: PrivateKeySigner = config.private_key.parse()?;
    let exchange_addr = signer.address().into_array();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(config.rpc_url.parse()?);
    let state: SharedState = Arc::new(Mutex::new(State::new(
        &config,
        config.chain_id,
        exchange_addr,
    )?));

    log_burn_addresses(&state);
    spawn_http_server(state.clone(), config.port);

    let mut last_block = catch_up(&state, &provider, &config).await?;

    loop {
        last_block = indexer_step(&state, &provider, &config, last_block).await?;
        do_update_root(&state, &provider, &config).await?;
        do_withdraw(&state, &provider, &config).await?;
        tokio::time::sleep(Duration::from_secs(config.poll_interval_secs)).await;
    }
}

async fn indexer_step(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    last_block: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let latest = provider.get_block_number().await?;
    if latest <= last_block {
        return Ok(last_block);
    }
    let transfers = fetch_transfers(provider, config.token, last_block + 1, latest).await?;

    let mut witnesses = Vec::new();
    {
        let mut s = state.lock().unwrap();
        for (to, value) in transfers {
            if let Some(w) = apply_transfer(&mut s, to, value, true)? {
                witnesses.push(w);
            }
        }
        if !witnesses.is_empty() {
            match &mut s.pending {
                Some((_, existing)) => existing.extend(witnesses),
                None => {
                    let z_0 = vec![Fr::zero(), s.chain.state(), s.tree.root()];
                    s.pending = Some((z_0, witnesses));
                }
            }
        }
    }

    Ok(latest)
}

async fn deposits(AxumState(state): AxumState<SharedState>) -> impl IntoResponse {
    let s = state.lock().unwrap();
    let list: Vec<_> = s
        .deposits
        .iter()
        .map(|(addr, (value, _root_index, idx))| {
            serde_json::json!({
                "address": format!("0x{}", hex::encode(addr)),
                "value": value.to_string(),
                "tree_index": idx,
            })
        })
        .collect();
    Json(serde_json::json!({ "deposits": list })).into_response()
}

async fn do_update_root(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let (z_0, witnesses) = {
        let mut s = state.lock().unwrap();
        if s.tree.len() < TREE_CAPACITY {
            return Ok(()); // not full yet
        }
        s.pending.take().expect("pending witnesses")
    };

    let circuit = RootTransitionCircuit::new(())?;
    let calldata = prove_root_transition(circuit, z_0, witnesses)?;
    let proof_arr = decode_opaque_proof::<32>(&calldata);

    let contract = IVerifier::new(config.verifier, provider);
    let tx = contract.updateRoot(proof_arr).send().await?;
    let receipt = tx.get_receipt().await?;
    println!("updateRoot tx = {}", receipt.transaction_hash);

    // Move the full tree into finalized_trees and start a fresh one.
    {
        let mut s = state.lock().unwrap();
        let finalized = std::mem::replace(&mut s.tree, MerkleTree::new(TREE_DEPTH));
        s.finalized_trees.push(finalized);
        s.pending = None;
    }
    Ok(())
}

async fn do_withdraw(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tweak, exchange_addr, chain_id, deposits) = {
        let s = state.lock().unwrap();
        (s.tweak, s.exchange_addr, s.chain_id, s.deposits.clone())
    };

    let recipient = recipient(chain_id, exchange_addr, tweak);

    // Group deposits by rootIndex.
    let mut by_tree: HashMap<usize, Vec<(usize, Fr, Fr)>> = HashMap::new();
    {
        let s = state.lock().unwrap();
        for (addr, (value, root_index, tree_index)) in &deposits {
            let secret = s.secret_by_addr[addr];
            by_tree
                .entry(*root_index)
                .or_default()
                .push((*tree_index, secret, *value));
        }
    }

    for (root_index, mut receipts) in by_tree {
        if receipts.len() < 2 {
            continue; // decider requires >= 2 folded steps
        }
        receipts.sort_by_key(|&(idx, _, _)| idx);

        let (transfer_root, witnesses) = {
            let s = state.lock().unwrap();
            let tree = &s.finalized_trees[root_index];
            let transfer_root = tree.root();
            let mut witnesses = Vec::with_capacity(receipts.len());
            for (idx, secret, value) in receipts {
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
            (transfer_root, witnesses)
        };

        let z_0 = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];
        let circuit = WithdrawCircuit::new(WithdrawParams { pow_bits: 20 })?;
        let calldata = prove_withdraw(circuit, z_0, witnesses)?;
        let proof_arr = decode_opaque_proof::<34>(&calldata);

        let contract = IVerifier::new(config.verifier, provider);
        let tx = contract
            .withdraw(
                U256::from(chain_id),
                Address::from(exchange_addr),
                B256::from(tweak),
                U256::from(root_index as u64),
                proof_arr,
            )
            .send()
            .await?;
        let receipt = tx.get_receipt().await?;
        println!(
            "withdraw tx (tree {root_index}) = {}",
            receipt.transaction_hash
        );
    }

    // Rotate tweak for the next batch.
    let mut rng = rand::thread_rng();
    let mut new_tweak = [0u8; 32];
    use rand::RngCore;
    rng.fill_bytes(&mut new_tweak);
    state.lock().unwrap().rotate_tweak(new_tweak)?;

    Ok(())
}

async fn catch_up(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<u64, Box<dyn std::error::Error>> {
    let latest = provider.get_block_number().await?;
    let transfers = fetch_transfers(provider, config.token, config.last_block + 1, latest).await?;

    // How many trees are already finalized on-chain?
    let on_chain_roots: Vec<Fr> = {
        let contract = IVerifier::new(config.verifier, provider);
        let n: u64 = contract
            .transferRootsLength()
            .call()
            .await?
            .try_into()
            .unwrap();
        let mut roots = Vec::with_capacity(n as usize);
        for i in 0..n {
            let r: U256 = contract.transferRoots(U256::from(i)).call().await?;
            roots.push(u256_to_fr(r));
        }
        roots
    };

    let mut witnesses = Vec::new();
    let mut z_0 = vec![Fr::zero(), Fr::zero(), Fr::zero()];
    let mut in_new = false;
    {
        let mut s = state.lock().unwrap();
        for (to, value) in transfers {
            // Finalize a tree when it fills, matching on-chain roots.
            if s.tree.len() == TREE_CAPACITY {
                let finalized = std::mem::replace(&mut s.tree, MerkleTree::new(TREE_DEPTH));
                s.finalized_trees.push(finalized);
                s.pending = None;
                in_new = false;
            }
            let is_historical = s.finalized_trees.len() < on_chain_roots.len();
            if is_historical {
                apply_transfer(&mut s, to, value, false)?;
            } else {
                if !in_new {
                    z_0 = vec![Fr::zero(), s.chain.state(), s.tree.root()];
                    in_new = true;
                }
                if let Some(w) = apply_transfer(&mut s, to, value, true)? {
                    witnesses.push(w);
                }
            }
        }
        if !witnesses.is_empty() {
            s.pending = Some((z_0, witnesses));
        }
    }

    do_update_root(state, provider, config).await?;
    Ok(latest)
}

// ---- HTTP handlers ----

async fn health() -> &'static str {
    "ok"
}

async fn deposit_address(AxumState(state): AxumState<SharedState>) -> impl IntoResponse {
    let mut s = state.lock().unwrap();
    if s.next_index >= s.burn_addresses.len() {
        return (StatusCode::NOT_FOUND, "no deposit addresses available").into_response();
    }
    let addr = s.burn_addresses[s.next_index];
    s.next_index += 1;
    Json(serde_json::json!({ "address": format!("0x{}", hex::encode(addr)) })).into_response()
}

async fn status(AxumState(state): AxumState<SharedState>) -> impl IntoResponse {
    let s = state.lock().unwrap();
    Json(serde_json::json!({
        "index": s.chain.index(),
        "root": s.tree.root().to_string(),
        "deposits": s.deposits.len(),
        "available": s.burn_addresses.len().saturating_sub(s.next_index),
    }))
    .into_response()
}
