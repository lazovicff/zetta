//! Worker: three phases per tick.
//! Phase 1 `prepare` — catch the local mirror up to the proven on-chain
//!   state, derived exclusively from chain + DB. Knows nothing about later
//!   phases.
//! Phase 2 (next) — apply the interval's new transfers on an isolated copy,
//!   prove + submit updateRoot and withdraws, discard the copy.
//! Phase 3 (after) — user payouts, fully independent of 1–2.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_grumpkin::{Affine as G2Affine, Projective as G2};
use folding_schemes::frontend::FCircuit;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::burn::{address_to_fr, recipient};
use crate::config::Config;
use crate::server::db::{Db, fr_to_u256};
use crate::server::state::State;
use crate::server::{IToken, IVerifier, SharedState, Transfer, u256_to_fr};

use alloy::primitives::B256;
use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::Zero; // replace `use ark_bn254::Fr;` with the line above
use std::time::Instant;

use crate::server::{decode_opaque_proof, fq_to_u256};
use crate::tree::TREE_DEPTH;
use crate::zkp::{
    RootTransitionCircuit, RootTransitionWitness, SingleRootTransitionCircuit,
    SingleWithdrawCircuit, WithdrawCircuit, WithdrawWitness, poseidon2, prove_root_transition,
    prove_single_root_transition, prove_single_withdraw, prove_withdraw,
};

/// Phase-1 output: ground truth derived exclusively from chain + DB,
/// snapshotted at `latest_block` — after the reservation, so the transfer
/// window covers everything up to `reserved_index`.
pub struct Prepared {
    /// Mirror of the PROVEN state: transfers[0 .. transferIndex) replayed.
    pub state: State,
    /// Every Transfer since deployment, ordered by (block, log index).
    pub transfers: Vec<([u8; 20], Fr)>,
    /// On-chain totalWithdrawn[recipient]: lifetime sum already teleported.
    pub withdrawn: U256,
    /// Epoch target pinned by the reservation (token head at reserve time).
    pub reserved_index: u64,
    pub reserved_chain: Fr,
    pub latest_block: u64,
}

pub async fn run(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    db: &Db,
    exchange_addr: [u8; 20],
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if let Err(e) = tick(state, provider, config, db, exchange_addr).await {
            warn!(error = %e, "tick failed");
        }
        tokio::time::sleep(Duration::from_secs(config.poll_interval_secs)).await;
    }
}

/// One interval: reserve → prepare → process. Phase 3 slots in after process.
async fn tick(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    db: &Db,
    exchange_addr: [u8; 20],
) -> Result<(), Box<dyn std::error::Error>> {
    reserve(provider, config).await?;
    let p = prepare(provider, config, db, exchange_addr).await?;
    debug!(
        stage = "prepare",
        proven = p.state.chain.index(),
        block = p.latest_block,
        "caught up"
    );
    *state.lock().unwrap() = p.state.clone(); // interval boundary: single atomic swap
    process(provider, config, &p).await?;
    payouts(provider, config, db).await?;
    Ok(())
}

/// Step 0 — pin the epoch target on-chain BEFORE the phase-1 snapshot, so the
/// snapshot's transfer window provably covers everything up to the reservation.
async fn reserve(
    provider: &impl Provider,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let rc = send_and_confirm(|| {
        let c = verifier.clone();
        async move { c.reserveHashChain().send().await }
    })
    .await?;
    debug!(stage = "reserve", tx = %rc.transaction_hash, "hash chain reserved");
    Ok(())
}

/// Phase 1 — preparation. Rebuilds the proven mirror from scratch each call:
/// registrations from the DB; proven root / hash chain / withdraw watermark /
/// reservation from the verifier; transfers from token events.
async fn prepare(
    provider: &impl Provider,
    config: &Config,
    db: &Db,
    exchange_addr: [u8; 20],
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let recip = recipient(config.chain_id, exchange_addr, config.tweak);

    // Chain facts, all at the same block: what the contract has already
    // processed + the epoch target pinned by `reserve`.
    let latest = provider.get_block_number().await?;
    let block = alloy::eips::BlockId::number(latest);
    let proven: u64 = verifier
        .transferIndex()
        .block(block)
        .call()
        .await?
        .try_into()?;
    let on_chain_root = u256_to_fr(verifier.transferRoot().block(block).call().await?);
    let on_chain_chain = u256_to_fr(verifier.transferHashChain().block(block).call().await?);
    let withdrawn = verifier
        .totalWithdrawn(fr_to_u256(recip))
        .block(block)
        .call()
        .await?;
    let reserved_index: u64 = verifier
        .reservedIndex()
        .block(block)
        .call()
        .await?
        .try_into()?;
    let reserved_chain = u256_to_fr(verifier.reservedHashChain().block(block).call().await?);

    let transfers = fetch_transfers(provider, config.token, config.last_block + 1, latest).await?;
    if (transfers.len() as u64) < proven {
        return Err(format!(
            "contract proves {proven} transfers but only {} events found (reorg?)",
            transfers.len()
        )
        .into());
    }
    if reserved_index < proven || reserved_index > transfers.len() as u64 {
        return Err(format!(
            "reservation [{proven}..{reserved_index}] outside snapshot ({} transfers)",
            transfers.len()
        )
        .into());
    }

    let mut s = State::new(config, config.chain_id, exchange_addr)?;
    hydrate_registrations(&mut s, db).await?;
    for &(to, value) in &transfers[..proven as usize] {
        apply_transfer(&mut s, to, value)?;
    }

    if s.tree.root() != on_chain_root || s.chain.state() != on_chain_chain {
        return Err(format!(
            "local mirror diverged from contract: root {} vs {on_chain_root}, chain {} vs {on_chain_chain}",
            s.tree.root(),
            s.chain.state(),
        )
        .into());
    }

    Ok(Prepared {
        state: s,
        transfers,
        withdrawn,
        reserved_index,
        reserved_chain,
        latest_block: latest,
    })
}

/// Phase 2 — interval processing. Commits the epoch's transfers (updateRoot)
/// and teleports proven deposits of registered addresses (withdraw), all on
/// an isolated copy of the phase-1 state, dropped on return. The shared state
/// is never touched here; phase 1 re-derives it next tick.
async fn process(
    provider: &impl Provider,
    config: &Config,
    prepared: &Prepared,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut work = prepared.state.clone();
    let proven = work.chain.index();

    // ---- epoch: prove transfers[proven..reserved_index] and advance the root ----
    if prepared.reserved_index > proven {
        let z_0 = vec![Fr::from(proven), work.chain.state(), work.tree.root()];
        let mut witnesses = Vec::with_capacity((prepared.reserved_index - proven) as usize);
        for &(to, value) in &prepared.transfers[proven as usize..prepared.reserved_index as usize] {
            witnesses.push(commit_transfer(&mut work, to, value)?);
        }
        if work.chain.state() != prepared.reserved_chain {
            return Err("hash chain diverged from reserved snapshot".into());
        }
        submit_update_root(provider, config, &work, z_0, witnesses).await?;
    }

    // ---- withdraws: commit every proven deposit of registered addresses ----
    if let Some(sum) = withdraw_witnesses(&work).map(|_| sum_deposits(&work)) {
        if sum <= prepared.withdrawn {
            debug!(stage = "withdraw", "nothing new beyond totalWithdrawn");
            return Ok(());
        }
        submit_withdraws(provider, config, &work).await?;
    }
    Ok(()) // `work` dropped; next tick starts from the reservation again
}

/// Phase 3 — payouts: settle DB 'pending' user withdraws as token transfers.
/// Touches nothing from phases 1–2; sequential because every tx here shares
/// the exchange key.
async fn payouts(
    provider: &impl Provider,
    config: &Config,
    db: &Db,
) -> Result<(), Box<dyn std::error::Error>> {
    let pendings = db.pending_withdraws().await?;
    if pendings.is_empty() {
        return Ok(());
    }
    info!(
        stage = "payout",
        count = pendings.len(),
        "processing pending withdraws"
    );
    let token = IToken::new(config.token, provider);

    for w in pendings {
        let payout = w.amount.saturating_sub(w.fee);
        let ref_ = w.ref_.clone();
        let res = send_and_confirm(|| {
            let t = token.clone();
            async move {
                t.transfer(Address::from(w.destination), payout)
                    .send()
                    .await
            }
        })
        .await;
        match res {
            Ok(rc) if rc.status() => {
                db.settle_withdraw(&ref_, "succeeded", Some(rc.transaction_hash.0), None)
                    .await?;
                info!(stage = "payout", ref_ = %ref_, tx = %rc.transaction_hash, "paid out");
            }
            Ok(rc) => {
                db.settle_withdraw(&ref_, "failed", None, Some("payout reverted"))
                    .await?;
                warn!(stage = "payout", ref_ = %ref_, tx = %rc.transaction_hash, "payout reverted");
            }
            Err(e) => {
                // Unknown fate: the tx may have been broadcast before the
                // error. Do NOT settle 'failed' (that would free the
                // reservation while tokens may have moved) — leave 'pending'
                // for the operator to resolve.
                warn!(stage = "payout", ref_ = %ref_, error = %e, "outcome unknown — left pending");
            }
        }
    }
    Ok(())
}

async fn submit_update_root(
    provider: &impl Provider,
    config: &Config,
    work: &State,
    z_0: Vec<Fr>,
    witnesses: Vec<RootTransitionWitness>,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    if witnesses.len() == 1 {
        info!(stage = "commit", "proving one-leaf transition (Groth16)");
        let z_1 = [
            Fr::from(work.chain.index()),
            work.chain.state(),
            work.tree.root(),
        ];
        let circuit = SingleRootTransitionCircuit {
            z_0: [z_0[0], z_0[1], z_0[2]],
            z_1,
            witness: witnesses[0].clone(),
        };
        let (proof, _) = prove_single_root_transition(circuit)?;
        let (a, b, c) = pack_groth16(&proof);
        let signals: [U256; 6] = [
            fr_to_u256(z_0[0]),
            fr_to_u256(z_0[1]),
            fr_to_u256(z_0[2]),
            fr_to_u256(z_1[0]),
            fr_to_u256(z_1[1]),
            fr_to_u256(z_1[2]),
        ];
        let rc = send_and_confirm(|| {
            let c_ = verifier.clone();
            async move { c_.updateRootSingle(a, b, c, signals).send().await }
        })
        .await?;
        info!(stage = "commit", tx = %rc.transaction_hash, gas = rc.gas_used, "updateRootSingle confirmed");
    } else {
        info!(
            stage = "commit",
            steps = witnesses.len(),
            "proving root transition (Nova + decider)"
        );
        let t = Instant::now();
        let calldata = prove_root_transition(RootTransitionCircuit::new(())?, z_0, witnesses)?;
        info!(stage = "commit", elapsed = ?t.elapsed(), "root proof done");
        let proof = decode_opaque_proof::<32>(&calldata);
        let rc = send_and_confirm(|| {
            let c_ = verifier.clone();
            async move { c_.updateRoot(proof).send().await }
        })
        .await?;
        info!(stage = "commit", tx = %rc.transaction_hash, gas = rc.gas_used, "updateRoot confirmed");
    }
    Ok(())
}

async fn submit_withdraws(
    provider: &impl Provider,
    config: &Config,
    work: &State,
) -> Result<(), Box<dyn std::error::Error>> {
    let recipient = recipient(work.chain_id, work.exchange_addr, work.tweak);
    let verifier = IVerifier::new(config.verifier, provider);
    let witnesses = match withdraw_witnesses(work) {
        Some(w) => w,
        None => return Ok(()),
    };

    if witnesses.len() == 1 {
        info!(
            stage = "withdraw",
            kind = "single",
            "proving single withdraw (Groth16)"
        );
        let circuit = SingleWithdrawCircuit {
            transfer_root: work.tree.root(),
            recipient,
            index_with_offset: Fr::zero(),
            witness: witnesses[0].clone(),
        };
        let value = circuit.witness.value;
        let (proof, _) = prove_single_withdraw(circuit)?;
        let (a, b, c) = pack_groth16(&proof);
        let signals: [U256; 3] = [
            fr_to_u256(work.tree.root()),
            fr_to_u256(recipient),
            fr_to_u256(value),
        ];
        let rc = send_and_confirm(|| {
            let c_ = verifier.clone();
            async move {
                c_.withdrawSingle(
                    U256::from(work.chain_id),
                    Address::from(work.exchange_addr),
                    B256::from(work.tweak),
                    a,
                    b,
                    c,
                    signals,
                )
                .send()
                .await
            }
        })
        .await?;
        info!(stage = "withdraw", tx = %rc.transaction_hash, gas = rc.gas_used, "withdrawSingle confirmed");
    } else {
        info!(
            stage = "withdraw",
            receipts = witnesses.len(),
            "proving batch withdraw (Nova + decider)"
        );
        let z_0 = vec![Fr::zero(), Fr::zero(), work.tree.root(), recipient];
        let calldata = prove_withdraw(WithdrawCircuit::new(())?, z_0, witnesses)?;
        let proof = decode_opaque_proof::<34>(&calldata);
        let rc = send_and_confirm(|| {
            let c_ = verifier.clone();
            async move {
                c_.withdraw(
                    U256::from(work.chain_id),
                    Address::from(work.exchange_addr),
                    B256::from(work.tweak),
                    proof,
                )
                .send()
                .await
            }
        })
        .await?;
        info!(stage = "withdraw", tx = %rc.transaction_hash, gas = rc.gas_used, "withdraw confirmed");
    }
    Ok(())
}

/// Withdraw witnesses for every deposit in the working copy (all proven,
/// after the epoch above or by phase 1). Returns None when there are none.
fn withdraw_witnesses(s: &State) -> Option<Vec<WithdrawWitness>> {
    let mut receipts: Vec<(usize, G2, G2, Fq, Fr, Fr)> = Vec::new();
    for (addr, ds) in &s.deposits {
        let (Some(&pk), Some(&(sig_r, sig_z)), Some(&salt)) = (
            s.pubkey_by_addr.get(addr),
            s.sig_by_addr.get(addr),
            s.salt_by_addr.get(addr),
        ) else {
            continue;
        };
        for &(value, idx) in ds {
            receipts.push((idx, pk, sig_r, sig_z, salt, value));
        }
    }
    if receipts.is_empty() {
        return None;
    }
    receipts.sort_by_key(|r| r.0);
    Some(
        receipts
            .into_iter()
            .map(|(idx, pubkey, sig_r, sig_z, salt, value)| {
                let mut merkle_path = [Fr::zero(); TREE_DEPTH];
                merkle_path.copy_from_slice(&s.tree.proof(idx));
                WithdrawWitness {
                    pubkey,
                    sig_r,
                    sig_z,
                    salt,
                    value,
                    index: Fr::from(idx as u64),
                    merkle_path,
                }
            })
            .collect(),
    )
}

/// Apply one transfer to the working copy, recording the root-step witness.
fn commit_transfer(
    s: &mut State,
    to: [u8; 20],
    value: Fr,
) -> Result<RootTransitionWitness, Box<dyn std::error::Error>> {
    let mut merkle_path = [Fr::zero(); TREE_DEPTH];
    merkle_path.copy_from_slice(&s.tree.proof_for_empty(s.tree.len()));
    let witness = RootTransitionWitness {
        to: address_to_fr(to),
        value,
        merkle_path,
    };
    apply_transfer(s, to, value)?;
    Ok(witness)
}

/// Lifetime sum of all deposits held by registered addresses.
fn sum_deposits(s: &State) -> U256 {
    s.deposits
        .values()
        .flatten()
        .fold(U256::ZERO, |acc, &(v, _)| acc + fr_to_u256(v))
}

/// Solidity verifier layout: G1 (x,y); G2 with c1 before c0 per contract convention.
fn pack_groth16(p: &ark_groth16::Proof<Bn254>) -> ([U256; 2], [[U256; 2]; 2], [U256; 2]) {
    (
        [fq_to_u256(p.a.x), fq_to_u256(p.a.y)],
        [
            [fq_to_u256(p.b.x.c1), fq_to_u256(p.b.x.c0)],
            [fq_to_u256(p.b.y.c1), fq_to_u256(p.b.y.c0)],
        ],
        [fq_to_u256(p.c.x), fq_to_u256(p.c.y)],
    )
}

/// Latest registration per address, re-validated on load; malformed rows skipped.
async fn hydrate_registrations(s: &mut State, db: &Db) -> Result<(), Box<dyn std::error::Error>> {
    for r in db.latest_registrations().await? {
        let pk = G2Affine::new_unchecked(r.pubkey_x, r.pubkey_y);
        let rr = G2Affine::new_unchecked(r.sig_r_x, r.sig_r_y);
        if !(pk.is_on_curve() && rr.is_on_curve()) {
            warn!(stage = "prepare", addr = %hex::encode(r.address), "skipping invalid registration");
            continue;
        }
        s.pubkey_by_addr.insert(r.address, G2::from(pk));
        s.sig_by_addr.insert(r.address, (G2::from(rr), r.sig_z));
        s.salt_by_addr.insert(r.address, r.salt);
    }
    Ok(())
}

/// Replay one proven transfer: tree insert + hash-chain step + ledger entries.
fn apply_transfer(
    s: &mut State,
    to: [u8; 20],
    value: Fr,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = s.tree.len();
    s.tree.insert(poseidon2(address_to_fr(to), value)?);
    s.chain.apply(to, value);
    *s.credits.entry(to).or_default() += fr_to_u256(value);
    if s.pubkey_by_addr.contains_key(&to) {
        s.deposits.entry(to).or_default().push((value, index));
    }
    Ok(())
}

/// Every Transfer in [from_block, to_block], ordered by (block, log index);
/// mints/burns excluded, matching the on-chain hash-chain rule.
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
    let mut out = Vec::with_capacity(logs.len());
    for log in &logs {
        let decoded = log.log_decode::<Transfer>()?;
        let d = decoded.data();
        if d.from == Address::ZERO || d.to == Address::ZERO {
            continue;
        }
        out.push((d.to.into_array(), u256_to_fr(d.value)));
    }

    Ok(out)
}

pub async fn send_and_confirm<F, Fut, E>(
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

pub fn log_recipient(state: &SharedState) {
    let s = state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    info!(stage = "boot", recipient = %r, "exchange recipient");
}
