use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_bn254::{Fq, Fr};
use ark_ff::Zero;
use ark_grumpkin::{Affine as G2Affine, Projective as G2};

use folding_schemes::frontend::FCircuit;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::burn::{address_to_fr, recipient};
use crate::config::Config;
use crate::server::db::{Db, fr_to_u256};
use crate::server::state::State;
use crate::server::{
    IVerifier, SharedState, Transfer, decode_opaque_proof, fq_to_u256, u256_to_fr,
};
use crate::tree::TREE_DEPTH;
use crate::zkp::{
    RootTransitionCircuit, RootTransitionWitness, SingleRootTransitionCircuit,
    SingleWithdrawCircuit, WithdrawCircuit, WithdrawWitness, prove_root_transition,
    prove_single_withdraw, prove_withdraw,
};
use crate::zkp::{poseidon2, prove_single_root_transition};

pub async fn run(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // ---- initial chain sync, once ----
    let mut last_block = catch_up(&state, &provider, &config).await?;
    tracing::info!(stage = "catchup", last_block, "catch-up complete");

    loop {
        last_block = indexer_step(state, provider, config, last_block).await?;
        if let Some((z_0, witnesses)) = commit_leaves(state, provider, config).await? {
            do_update_root(state, provider, config, z_0, witnesses).await?;
        }
        do_withdraw(state, provider, config).await?;
        debug!(stage = "idle", "sleeping {}s", config.poll_interval_secs);
        tokio::time::sleep(Duration::from_secs(config.poll_interval_secs)).await;
    }
}

async fn send_and_confirm<F, Fut, E>(
    send: F,
) -> Result<alloy::rpc::types::TransactionReceipt, Box<dyn std::error::Error>>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<
            Output = Result<
                alloy::providers::PendingTransactionBuilder<alloy::network::Ethereum>,
                E,
            >,
        >,
    E: ToString + std::error::Error + 'static,
{
    match send().await {
        Ok(p) => Ok(p.get_receipt().await?),
        Err(e) if e.to_string().contains("-32003") => {
            warn!(stage = "tx", "nonce too low — retrying with fresh nonce");
            Ok(send().await?.get_receipt().await?)
        }
        Err(e) => Err(e.to_string().into()),
    }
}

/// Load persisted registrations into the in-memory state.
pub async fn hydrate_registrations(
    state: &SharedState,
    db: &Db,
) -> Result<(), Box<dyn std::error::Error>> {
    let regs = db.latest_registrations().await?;
    let mut s = state.lock().unwrap();
    for r in &regs {
        let pk = G2Affine::new_unchecked(r.pubkey_x, r.pubkey_y);
        let rr = G2Affine::new_unchecked(r.sig_r_x, r.sig_r_y);
        if !(pk.is_on_curve() && rr.is_on_curve()) {
            warn!(stage = "boot", addr = %hex::encode(r.address), "skipping invalid registration");
            continue;
        }
        s.pubkey_by_addr.insert(r.address, G2::from(pk));
        s.sig_by_addr.insert(r.address, (G2::from(rr), r.sig_z));
        s.salt_by_addr.insert(r.address, r.salt);
    }
    info!(stage = "boot", count = regs.len(), "hydrated registrations");
    Ok(())
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

/// Insert one transfer into tree + hash chain + credits/deposits.
/// Returns the root-transition witness when `build_witness` is set.
fn apply_transfer(
    s: &mut State,
    to: [u8; 20],
    value: Fr,
    build_witness: bool,
) -> Result<Option<RootTransitionWitness>, Box<dyn std::error::Error>> {
    let to_fr = address_to_fr(to);
    let index = s.tree.len();
    let witness = if build_witness {
        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&s.tree.proof_for_empty(index));
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
        s.deposits.entry(to).or_default().push((value, index));
    }
    Ok(witness)
}

pub fn log_recipient(state: &SharedState) {
    let s = state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    info!(stage = "boot", recipient = %r, "exchange recipient");
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
    info!(
        stage = "indexer",
        from = last_block + 1,
        to = latest,
        "fetching transfers"
    );
    let transfers = fetch_transfers(provider, config.token, last_block + 1, latest).await?;
    if !transfers.is_empty() {
        info!(
            stage = "indexer",
            count = transfers.len(),
            "queued transfers"
        );
        state.lock().unwrap().uncommitted_leaves.extend(transfers);
    }
    Ok(latest)
}

/// Reserve the on-chain hash-chain snapshot, then insert queued leaves until
/// the local chain reaches it. Returns (z_0, witnesses) for the root
/// transition, or None when there is nothing new to commit.
async fn commit_leaves(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<Option<(Vec<Fr>, Vec<RootTransitionWitness>)>, Box<dyn std::error::Error>> {
    let contract = IVerifier::new(config.verifier, provider);
    send_and_confirm(|| {
        let contract = contract.clone();
        async move { contract.reserveHashChain().send().await }
    })
    .await?;
    let reserved_index: u64 = contract.reservedIndex().call().await?.try_into()?;
    let reserved_hash_chain = u256_to_fr(contract.reservedHashChain().call().await?);
    info!(stage = "commit", reserved_index, "hash chain reserved");

    let mut s = state.lock().unwrap();
    if s.chain.index() >= reserved_index {
        return Ok(None);
    }

    let z_0 = vec![Fr::from(s.chain.index()), s.chain.state(), s.tree.root()];
    let mut witnesses = Vec::new();

    while s.chain.index() < reserved_index {
        let Some((to, value)) = s.uncommitted_leaves.pop_front() else {
            warn!(
                stage = "commit",
                local = s.chain.index(),
                reserved = reserved_index,
                "queue empty before reaching reservation — skipping epoch"
            );
            return Ok(None);
        };
        if let Some(w) = apply_transfer(&mut s, to, value, true)? {
            witnesses.push(w);
        }
    }

    debug_assert_eq!(s.chain.state(), reserved_hash_chain);
    info!(
        stage = "commit",
        leaves = witnesses.len(),
        "committed epoch leaves"
    );
    Ok(Some((z_0, witnesses)))
}

async fn do_update_root(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    z_0: Vec<Fr>,
    witnesses: Vec<RootTransitionWitness>,
) -> Result<(), Box<dyn std::error::Error>> {
    if witnesses.len() == 1 {
        info!(
            stage = "update_root",
            kind = "single",
            "proving one-leaf transition (Groth16)"
        );
        let witness = witnesses[0].clone();
        let z_1 = {
            let s = state.lock().unwrap();
            [Fr::from(s.chain.index()), s.chain.state(), s.tree.root()]
        };
        let circuit = SingleRootTransitionCircuit {
            z_0: [z_0[0], z_0[1], z_0[2]],
            z_1,
            witness,
        };
        let (proof, _) = prove_single_root_transition(circuit)?;
        let p_a = [fq_to_u256(proof.a.x), fq_to_u256(proof.a.y)];
        let p_b = [
            [fq_to_u256(proof.b.x.c1), fq_to_u256(proof.b.x.c0)],
            [fq_to_u256(proof.b.y.c1), fq_to_u256(proof.b.y.c0)],
        ];
        let p_c = [fq_to_u256(proof.c.x), fq_to_u256(proof.c.y)];
        let pub_signals: [U256; 6] = [
            fr_to_u256(z_0[0]),
            fr_to_u256(z_0[1]),
            fr_to_u256(z_0[2]),
            fr_to_u256(z_1[0]),
            fr_to_u256(z_1[1]),
            fr_to_u256(z_1[2]),
        ];

        let contract = IVerifier::new(config.verifier, provider);
        let receipt = send_and_confirm(|| {
            let contract = contract.clone();
            async move {
                contract
                    .updateRootSingle(p_a, p_b, p_c, pub_signals)
                    .send()
                    .await
            }
        })
        .await?;
        info!(stage = "update_root", tx = %receipt.transaction_hash, gas = receipt.gas_used, "updateRootSingle confirmed");

        let mut s = state.lock().unwrap();
        s.committed_index = s.tree.len() as u64;
        return Ok(());
    } else {
        info!(
            stage = "update_root",
            steps = witnesses.len(),
            "proving root transition (Nova IVC + Groth16 decider)"
        );
        let circuit = RootTransitionCircuit::new(())?;
        let prove_start = std::time::Instant::now();
        let calldata = prove_root_transition(circuit, z_0, witnesses)?;
        info!(stage = "update_root", elapsed = ?prove_start.elapsed(), "root-transition proof done");
        let proof_arr = decode_opaque_proof::<32>(&calldata);

        let contract = IVerifier::new(config.verifier, provider);
        info!(stage = "update_root", verifier = %config.verifier, "calling updateRoot(proof)");
        let receipt = send_and_confirm(|| {
            let contract = contract.clone();
            async move { contract.updateRoot(proof_arr).send().await }
        })
        .await?;
        info!(stage = "update_root", tx = %receipt.transaction_hash, gas = receipt.gas_used, "updateRoot confirmed");

        let mut s = state.lock().unwrap();
        s.committed_index = s.tree.len() as u64;
    }
    Ok(())
}

async fn do_withdraw(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Collect receipts for leaves already proven on-chain.
    let mut receipts: Vec<([u8; 20], usize, G2, G2, Fq, Fr, Fr)> = Vec::new();
    {
        let s = state.lock().unwrap();
        for (addr, ds) in &s.deposits {
            for (value, tree_index) in ds {
                if *tree_index as u64 >= s.committed_index {
                    continue;
                }
                let (Some(pubkey), Some((sig_r, sig_z)), Some(salt)) = (
                    s.pubkey_by_addr.get(addr),
                    s.sig_by_addr.get(addr),
                    s.salt_by_addr.get(addr),
                ) else {
                    continue;
                };
                receipts.push((*addr, *tree_index, *pubkey, *sig_r, *sig_z, *salt, *value));
            }
        }
    }
    if receipts.is_empty() {
        debug!(stage = "withdraw", "no committed deposits to withdraw");
        return Ok(());
    }
    receipts.sort_by_key(|r| r.1);
    let (tweak, exchange_addr, chain_id) = {
        let s = state.lock().unwrap();
        (s.tweak, s.exchange_addr, s.chain_id)
    };
    let recipient = recipient(chain_id, exchange_addr, tweak);
    let contract = IVerifier::new(config.verifier, provider);

    if receipts.len() == 1 {
        let (_, idx, pubkey, sig_r, sig_z, salt, value) = receipts[0].clone();
        info!(
            stage = "withdraw",
            kind = "single",
            "proving single withdraw (Groth16)"
        );

        let (transfer_root, witness) = {
            let s = state.lock().unwrap();
            let mut merkle_path = [Fr::zero(); TREE_DEPTH];
            merkle_path.copy_from_slice(&s.tree.proof(idx));
            (
                s.tree.root(),
                WithdrawWitness {
                    pubkey,
                    sig_r,
                    sig_z,
                    salt,
                    value,
                    index: Fr::from(idx as u64),
                    merkle_path,
                },
            )
        };

        let circuit = SingleWithdrawCircuit {
            transfer_root,
            recipient,
            index_with_offset: Fr::zero(),
            witness,
        };
        let (proof, _) = prove_single_withdraw(circuit)?;
        let p_a = [fq_to_u256(proof.a.x), fq_to_u256(proof.a.y)];
        let p_b = [
            [fq_to_u256(proof.b.x.c1), fq_to_u256(proof.b.x.c0)],
            [fq_to_u256(proof.b.y.c1), fq_to_u256(proof.b.y.c0)],
        ];
        let p_c = [fq_to_u256(proof.c.x), fq_to_u256(proof.c.y)];
        let pub_signals: [U256; 3] = [
            fr_to_u256(transfer_root),
            fr_to_u256(recipient),
            fr_to_u256(value),
        ];

        let receipt = send_and_confirm(|| {
            let contract = contract.clone();
            async move {
                contract
                    .withdrawSingle(
                        U256::from(chain_id),
                        Address::from(exchange_addr),
                        B256::from(tweak),
                        p_a,
                        p_b,
                        p_c,
                        pub_signals,
                    )
                    .send()
                    .await
            }
        })
        .await?;
        info!(stage = "withdraw", tx = %receipt.transaction_hash, gas = receipt.gas_used, "withdrawSingle confirmed");
    } else {
        info!(
            stage = "withdraw",
            kind = "batch",
            receipts = receipts.len(),
            "proving batch withdraw (Nova IVC + Groth16 decider)"
        );

        let (transfer_root, witnesses) = {
            let s = state.lock().unwrap();
            let transfer_root = s.tree.root();
            let mut witnesses = Vec::with_capacity(receipts.len());
            for (_, idx, pubkey, sig_r, sig_z, salt, value) in &receipts {
                let mut merkle_path = [Fr::zero(); TREE_DEPTH];
                merkle_path.copy_from_slice(&s.tree.proof(*idx));
                witnesses.push(WithdrawWitness {
                    pubkey: *pubkey,
                    sig_r: *sig_r,
                    sig_z: *sig_z,
                    salt: *salt,
                    value: *value,
                    index: Fr::from(*idx as u64),
                    merkle_path,
                });
            }
            (transfer_root, witnesses)
        };

        let z_0 = vec![Fr::zero(), Fr::zero(), transfer_root, recipient];
        let calldata = prove_withdraw(WithdrawCircuit::new(())?, z_0, witnesses)?;
        let proof_arr = decode_opaque_proof::<34>(&calldata);

        let receipt = send_and_confirm(|| {
            let contract = contract.clone();
            async move {
                contract
                    .withdraw(
                        U256::from(chain_id),
                        Address::from(exchange_addr),
                        B256::from(tweak),
                        proof_arr,
                    )
                    .send()
                    .await
            }
        })
        .await?;
        info!(stage = "withdraw", tx = %receipt.transaction_hash, gas = receipt.gas_used, "withdraw confirmed");
    }

    // Remove consumed deposits.
    let mut s = state.lock().unwrap();
    for (addr, idx) in receipts.iter().map(|r| (r.0, r.1)) {
        if let Some(ds) = s.deposits.get_mut(&addr) {
            ds.retain(|(_, i)| *i != idx);
        }
    }
    s.deposits.retain(|_, ds| !ds.is_empty());
    Ok(())
}

async fn catch_up(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
) -> Result<u64, Box<dyn std::error::Error>> {
    let latest = provider.get_block_number().await?;
    let transfers = fetch_transfers(provider, config.token, config.last_block + 1, latest).await?;

    let contract = IVerifier::new(config.verifier, provider);
    let on_chain_index: u64 = contract.transferIndex().call().await?.try_into()?;

    let mut s = state.lock().unwrap();
    for (i, (to, value)) in transfers.into_iter().enumerate() {
        if (i as u64) < on_chain_index {
            // Historical: already proven on-chain, replay without witnesses.
            apply_transfer(&mut s, to, value, false)?;
        } else {
            s.uncommitted_leaves.push_back((to, value));
        }
    }
    s.committed_index = on_chain_index;
    Ok(latest)
}
