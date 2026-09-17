use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolEvent;
use ark_bn254::{Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_grumpkin::{Affine as G2Affine, Projective as G2};
use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use folding_schemes::frontend::FCircuit;

use crate::burn::{address_to_fr, recipient, trim_to_160};
use crate::config::Config;
use crate::db::{Db, Registration, fr_to_u256, unix_now};
use crate::state::State;
use crate::tree::{MerkleTree, TREE_CAPACITY, TREE_DEPTH};
use crate::zkp::{
    RootTransitionCircuit, RootTransitionWitness, SingleWithdrawCircuit, WithdrawCircuit,
    WithdrawWitness, prove_root_transition, prove_single_withdraw, prove_withdraw,
};
use crate::zkp::{poseidon2, poseidon3};

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function updateRoot(uint256[32] proof) external;
        function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256 rootIndex, uint256[34] proof) external;
        function withdrawSingle(uint256 chainId, address addr, bytes32 tweak, uint256 rootIndex, uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[4] pubSignals) external;
        function transferIndex() external view returns (uint256);
        function transferRootsLength() external view returns (uint256);
        function transferRoots(uint256 index) external view returns (uint256);
    }
}

type SharedState = Arc<Mutex<State>>;

#[derive(Clone)]
struct AppState {
    state: SharedState,
    db: Db,
}

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn fq_to_u256(x: Fq) -> U256 {
    U256::from_be_slice(&crate::db::fr_to_blob(x))
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
    *s.credits.entry(to).or_default() += fr_to_u256(value);
    if s.pubkey_by_addr.contains_key(&to) {
        let root_index = s.finalized_trees.len();
        s.deposits
            .entry(to)
            .or_default()
            .push((value, root_index, index));
    }
    Ok(witness)
}

fn log_recipient(state: &SharedState) {
    let s = state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    println!("recipient = {}", r);
}

fn spawn_http_server(app: AppState, port: u16) {
    tokio::spawn(async move {
        let router = Router::new()
            .route("/health", get(health))
            .route("/recipient", get(current_recipient))
            .route("/register", post(register))
            .route("/deposits", get(deposits))
            .route("/balance/:pubkey_x", get(balance))
            .route("/cards", post(order_card))
            .route("/status", get(status))
            .with_state(app);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .unwrap();
        axum::serve(listener, router).await.unwrap();
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

    let db = Db::open(&config.database_url).await?;

    // Hydrate in-memory auth maps from the durable log.
    {
        let regs = db.latest_registrations().await?;
        let mut s = state.lock().unwrap();
        for r in &regs {
            let pk = G2Affine::new_unchecked(r.pubkey_x, r.pubkey_y);
            let rr = G2Affine::new_unchecked(r.sig_r_x, r.sig_r_y);
            if !(pk.is_on_curve() && rr.is_on_curve()) {
                eprintln!("skipping invalid registration 0x{}", hex::encode(r.address));
                continue;
            }
            s.pubkey_by_addr.insert(r.address, G2::from(pk));
            s.sig_by_addr.insert(r.address, (G2::from(rr), r.sig_z));
            s.salt_by_addr.insert(r.address, r.salt);
        }
        println!("hydrated {} registrations", regs.len());
    }

    log_recipient(&state);
    spawn_http_server(
        AppState {
            state: state.clone(),
            db,
        },
        config.port,
    );

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

async fn deposits(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    let list: Vec<_> = s
        .deposits
        .iter()
        .flat_map(|(addr, ds)| {
            ds.iter().map(move |(value, _root_index, idx)| {
                serde_json::json!({
                    "address": format!("0x{}", hex::encode(addr)),
                    "value": value.to_string(),
                    "tree_index": idx,
                })
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
    let (tweak, exchange_addr, chain_id) = {
        let s = state.lock().unwrap();
        (s.tweak, s.exchange_addr, s.chain_id)
    };
    let recipient = recipient(chain_id, exchange_addr, tweak);

    // Group deposits by rootIndex: (tree_index, P, R, z, salt, value).
    let mut by_tree: HashMap<usize, Vec<(usize, G2, G2, Fq, Fr, Fr)>> = HashMap::new();
    {
        let s = state.lock().unwrap();
        for (addr, ds) in &s.deposits {
            for (value, root_index, tree_index) in ds {
                if *root_index >= s.finalized_trees.len() {
                    continue; // tree not finalized yet
                }
                let (Some(pubkey), Some((sig_r, sig_z)), Some(salt)) = (
                    s.pubkey_by_addr.get(addr),
                    s.sig_by_addr.get(addr),
                    s.salt_by_addr.get(addr),
                ) else {
                    continue;
                };
                by_tree.entry(*root_index).or_default().push((
                    *tree_index,
                    *pubkey,
                    *sig_r,
                    *sig_z,
                    *salt,
                    *value,
                ));
            }
        }
    }

    for (root_index, mut receipts) in by_tree {
        if receipts.len() == 1 {
            let (idx, pubkey, sig_r, sig_z, salt, value) = receipts[0];

            let (transfer_root, witness) = {
                let s = state.lock().unwrap();
                let tree = &s.finalized_trees[root_index];
                let proof = tree.proof(idx);
                let mut merkle_path = [Fr::zero(); TREE_DEPTH];
                merkle_path.copy_from_slice(&proof);
                (
                    tree.root(),
                    WithdrawWitness {
                        pubkey,
                        sig_r,
                        sig_z,
                        salt,
                        value,
                        index: Fr::from(root_index as u64 * TREE_CAPACITY as u64 + idx as u64),
                        merkle_path,
                    },
                )
            };

            let index_with_offset = Fr::from(root_index as u64 * TREE_CAPACITY as u64);
            let circuit = SingleWithdrawCircuit {
                transfer_root,
                recipient,
                index_with_offset,
                witness,
            };
            let (proof, _public_inputs) = prove_single_withdraw(circuit)?;

            let p_a: [U256; 2] = [fq_to_u256(proof.a.x), fq_to_u256(proof.a.y)];
            let p_b: [[U256; 2]; 2] = [
                [fq_to_u256(proof.b.x.c1), fq_to_u256(proof.b.x.c0)],
                [fq_to_u256(proof.b.y.c1), fq_to_u256(proof.b.y.c0)],
            ];

            let p_c: [U256; 2] = [fq_to_u256(proof.c.x), fq_to_u256(proof.c.y)];
            let pub_signals: [U256; 4] = [
                fr_to_u256(transfer_root),
                fr_to_u256(recipient),
                fr_to_u256(index_with_offset),
                fr_to_u256(value),
            ];

            let contract = IVerifier::new(config.verifier, provider);
            let tx = contract
                .withdrawSingle(
                    U256::from(chain_id),
                    Address::from(exchange_addr),
                    B256::from(tweak),
                    U256::from(root_index as u64),
                    p_a,
                    p_b,
                    p_c,
                    pub_signals,
                )
                .send()
                .await?;
            let receipt = tx.get_receipt().await?;
            println!(
                "withdrawSingle tx (tree {root_index}) = {}",
                receipt.transaction_hash
            );
        } else {
            receipts.sort_by_key(|r| r.0);

            let (transfer_root, witnesses) = {
                let s = state.lock().unwrap();
                let tree = &s.finalized_trees[root_index];
                let transfer_root = tree.root();
                let mut witnesses = Vec::with_capacity(receipts.len());
                for (idx, pubkey, sig_r, sig_z, salt, value) in receipts {
                    let proof = tree.proof(idx);
                    let mut merkle_path = [Fr::zero(); TREE_DEPTH];
                    merkle_path.copy_from_slice(&proof);
                    witnesses.push(WithdrawWitness {
                        pubkey,
                        sig_r,
                        sig_z,
                        salt,
                        value,
                        index: Fr::from(root_index as u64 * TREE_CAPACITY as u64 + idx as u64),
                        merkle_path,
                    });
                }
                (transfer_root, witnesses)
            };

            let z_0 = vec![
                Fr::from(root_index as u64 * TREE_CAPACITY as u64),
                Fr::zero(),
                transfer_root,
                recipient,
            ];
            let circuit = WithdrawCircuit::new(())?;
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

            {
                let mut s = state.lock().unwrap();
                for ds in s.deposits.values_mut() {
                    ds.retain(|(_, ri, _)| *ri != root_index);
                }
                s.deposits.retain(|_, ds| !ds.is_empty());
            }
        }
    }

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

async fn current_recipient(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    Json(serde_json::json!({ "recipient": r.to_string() })).into_response()
}

#[derive(serde::Deserialize)]
struct RegisterReq {
    address: String,          // 0x + 40 hex
    pubkey: (String, String), // P = (x, y), decimal, grumpkin base field
    sig_r: (String, String),  // R = (x, y), decimal
    sig_z: String,            // z = k + e·x, decimal, grumpkin scalar field
    salt: String,             // burn preimage nonce, decimal
}

fn parse_hex20(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "expected 20 bytes".to_string())
}

fn parse_decimal_fr(s: &str) -> Result<Fr, String> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).ok_or("invalid decimal")?;
    Ok(Fr::from_be_bytes_mod_order(&n.to_bytes_be()))
}

fn parse_decimal_fq(s: &str) -> Result<Fq, String> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).ok_or("invalid decimal")?;
    Ok(Fq::from_be_bytes_mod_order(&n.to_bytes_be()))
}

async fn register(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    match register_inner(&app, req).await {
        Ok(()) => (StatusCode::OK, "registered").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn register_inner(app: &AppState, req: RegisterReq) -> Result<(), String> {
    let addr = parse_hex20(&req.address)?;
    let pk = G2Affine::new_unchecked(
        parse_decimal_fr(&req.pubkey.0)?,
        parse_decimal_fr(&req.pubkey.1)?,
    );
    let r = G2Affine::new_unchecked(
        parse_decimal_fr(&req.sig_r.0)?,
        parse_decimal_fr(&req.sig_r.1)?,
    );
    if !pk.is_on_curve() || !r.is_on_curve() {
        return Err("point not on curve".into());
    }
    use ark_ec::short_weierstrass::SWCurveConfig; // for GrumpkinConfig::GENERATOR
    if pk.is_zero() || pk.x == ark_grumpkin::GrumpkinConfig::GENERATOR.x {
        return Err("degenerate pubkey".into());
    }

    let z = parse_decimal_fq(&req.sig_z)?;
    let salt = parse_decimal_fr(&req.salt)?;

    let recipient = {
        let s = app.state.lock().unwrap();
        recipient(s.chain_id, s.exchange_addr, s.tweak)
    };

    // Address must be derivable from (pubkey, salt) under the current recipient.
    let derived = trim_to_160(poseidon3(recipient, pk.x, salt).map_err(|e| e.to_string())?);
    if derived != addr {
        return Err("address does not match (pubkey, salt) for current recipient".into());
    }

    // Schnorr: z·G == R + e·P with e = poseidon3(R.x, P.x, recipient).
    let e_fr = poseidon3(r.x, pk.x, recipient).map_err(|e| e.to_string())?;
    let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
    let lhs = (G2::generator() * z).into_affine();
    let rhs = (G2::from(r) + G2::from(pk) * e).into_affine();
    if lhs != rhs {
        return Err("bad signature".into());
    }

    let rec = Registration {
        address: addr,
        created_at: unix_now(),
        pubkey_x: pk.x,
        pubkey_y: pk.y,
        sig_r_x: r.x,
        sig_r_y: r.y,
        sig_z: z,
        salt,
        recipient,
        user_id: crate::ids::user_id(pk.x),
    };
    app.db
        .insert_registration(&rec)
        .await
        .map_err(|e| e.to_string())?;

    let mut s = app.state.lock().unwrap();
    s.pubkey_by_addr.insert(addr, G2::from(pk));
    s.sig_by_addr.insert(addr, (G2::from(r), z));
    s.salt_by_addr.insert(addr, salt);
    Ok(())
}

async fn balance(AxumState(app): AxumState<AppState>, Path(pk): Path<String>) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let deposited = {
        let s = app.state.lock().unwrap();
        let mut total = U256::ZERO;
        for (addr, sum) in &s.credits {
            if s.pubkey_by_addr.get(addr).map(|p| p.into_affine().x) == Some(pk_x) {
                total += *sum;
            }
        }
        total
    };
    match app.db.total_spent(pk_x).await {
        Ok(spent) => Json(serde_json::json!({
            "pubkey_x": pk,
            "deposited": deposited.to_string(),
            "spent": spent.to_string(),
            "balance": deposited.saturating_sub(spent).to_string(),
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct CardOrderReq {
    pubkey_x: String, // decimal
    amount: String,   // decimal token units
    deadline: String, // decimal: order sig valid while burn_index <= deadline
    sig_r: (String, String),
    sig_z: String,
}

async fn order_card(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<CardOrderReq>,
) -> impl IntoResponse {
    match order_card_inner(&app, req).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn order_card_inner(app: &AppState, req: CardOrderReq) -> Result<serde_json::Value, String> {
    let pk_x = parse_decimal_fr(&req.pubkey_x)?;
    let amount = parse_decimal_fr(&req.amount)?;
    let deadline = parse_decimal_fr(&req.deadline)?;
    let r = G2Affine::new_unchecked(
        parse_decimal_fr(&req.sig_r.0)?,
        parse_decimal_fr(&req.sig_r.1)?,
    );
    if !r.is_on_curve() {
        return Err("sig_r not on curve".into());
    }
    let z = parse_decimal_fq(&req.sig_z)?;

    let reg = app
        .db
        .latest_registration_by_pubkey(pk_x)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pubkey not registered".to_string())?;

    // Ownership proof: z·G == R + e·P with e = poseidon3(R.x, P.x, poseidon2(amount, deadline)).
    let pk = G2Affine::new_unchecked(reg.pubkey_x, reg.pubkey_y);
    if !pk.is_on_curve() {
        return Err("stored pubkey invalid".into());
    }
    let msg = poseidon2(amount, deadline).map_err(|e| e.to_string())?;
    let e_fr = poseidon3(r.x, pk.x, msg).map_err(|e| e.to_string())?;
    let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
    if (G2::generator() * z).into_affine() != (G2::from(r) + G2::from(pk) * e).into_affine() {
        return Err("bad order signature".into());
    }

    let (available, burn_index) = {
        let s = app.state.lock().unwrap();
        let mut total = U256::ZERO;
        for (addr, sum) in &s.credits {
            if s.pubkey_by_addr.get(addr).map(|p| p.into_affine().x) == Some(pk_x) {
                total += *sum;
            }
        }
        (total, s.chain.index())
    };
    if deadline < Fr::from(burn_index) {
        return Err("order signature expired".into());
    }
    if deadline > Fr::from(burn_index + 1_000_000) {
        return Err("deadline too far in the future".into());
    }

    let amount_u256 = fr_to_u256(amount);

    // 1. reserve funds (status 'pending') — Err means insufficient balance
    let provider_ref = format!("stub-{amount_u256}-{}", unix_now());
    let new_spent = app
        .db
        .try_spend(pk_x, amount_u256, available, "stub", &provider_ref)
        .await?;

    // 2. provider call — stub always succeeds; real provider goes here
    match Ok::<_, String>(()) {
        Ok(()) => {
            app.db
                .settle_order(&provider_ref, "succeeded", None)
                .await?;
            Ok(serde_json::json!({
                "amount": amount_u256.to_string(),
                "provider": "stub",
                "provider_ref": provider_ref,
                "lifetime_spent": new_spent.to_string(),
            }))
        }
        Err(e) => {
            let msg = e.to_string();
            app.db
                .settle_order(&provider_ref, "failed", Some(&msg))
                .await?;
            Err(format!("card provider failed: {msg}"))
        }
    }
}

async fn status(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({
        "index": s.chain.index(),
        "root": s.tree.root().to_string(),
        "deposits": s.deposits.len(),
        "registered": s.pubkey_by_addr.len(),
    }))
    .into_response()
}
