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

/// Max blocks per eth_getLogs call — under hosted-RPC range caps.
const LOG_CHUNK: u64 = 9_500;

/// Phase-1 output: progress bookkeeping. The mirror state itself is extended
/// in place and read back by later phases from the shared slot.
pub struct Prepared {
    /// transferIndex the mirror caught up to.
    pub proven: u64,
    /// Highest block whose events are now fully in the mirror (cursor target).
    pub last_replayed_block: Option<u64>,
    pub latest_block: u64,
}

pub async fn run(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    db: &Db,
) -> Result<(), Box<dyn std::error::Error>> {
    // Boot: full replay from the deployment block; afterwards incremental.
    let mut last_block = config.last_block;
    loop {
        if let Err(e) = tick(state, provider, config, db, &mut last_block).await {
            warn!(error = %e, "tick failed");
        }
        if let Err(e) = payouts(provider, config, db).await {
            warn!(stage = "payout", error = %e, "phase 3 failed");
        }
        tokio::time::sleep(Duration::from_secs(config.poll_interval_secs)).await;
    }
}

/// One interval: prepare → reserve → process. Payouts run separately in run().
async fn tick(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    db: &Db,
    last_block: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Phase 1: catch the mirror up to the finalized prefix [0..transferIndex).
    let mut next = state.lock().unwrap().clone(); // shared slot untouched on failure
    let p = prepare(&mut next, provider, config, db, *last_block + 1).await?;
    if let Some(b) = p.last_replayed_block {
        *last_block = b;
    }
    debug!(
        stage = "prepare",
        proven = p.proven,
        block = p.latest_block,
        "caught up"
    );
    *state.lock().unwrap() = next;

    // Phase 2: reserve at the tip, then process the fresh chunk.
    reserve(provider, config).await?;
    process(state, provider, config, *last_block).await
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

/// Phase 1 — preparation. Extends the mirror with the proven prefix of the
/// fresh window: registrations from the DB; proven root / hash chain /
/// withdraw watermark / reservation from the verifier; events since the last
/// prepared block.
async fn prepare(
    s: &mut State,
    provider: &impl Provider,
    config: &Config,
    db: &Db,
    from_block: u64,
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);

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
    let reserved_index: u64 = verifier
        .reservedIndex()
        .block(block)
        .call()
        .await?
        .try_into()?;

    hydrate_registrations(s, db).await?;

    let events = fetch_transfers(provider, config.token, from_block, latest).await?;
    let base = s.chain.index();
    if proven < base || base + events.len() as u64 <= proven.saturating_sub(1) {
        return Err(format!(
            "window from block {from_block} can't cover proven index {proven} (base {base}, {} events)",
            events.len()
        )
        .into());
    }
    if reserved_index < proven || reserved_index > base + events.len() as u64 {
        return Err(format!(
            "reservation [{proven}..{reserved_index}] outside window (base {base}, {} events)",
            events.len()
        )
        .into());
    }

    // Replay the proven prefix of the window.
    let mut last_replayed_block = None;
    for &(blk, to, value) in &events {
        if s.chain.index() >= proven {
            break;
        }
        apply_transfer(s, to, value)?;
        last_replayed_block = Some(blk);
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
        proven,
        last_replayed_block,
        latest_block: latest,
    })
}

/// Phase 2 — interval processing. Commits the epoch's transfers (updateRoot)
/// and teleports proven deposits of registered addresses (withdraw), all on
/// an isolated copy of the shared state, dropped on return. Every input is
/// read here: reservation, watermark and events from chain, state from the
/// shared slot.
async fn process(
    state: &SharedState,
    provider: &impl Provider,
    config: &Config,
    from_block: u64, // last prepared block; events after it start at `proven`
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let mut work = state.lock().unwrap().clone(); // isolated copy — discarded at return

    // ---- epoch: prove transfers[proven..reserved_index] and advance the root ----
    let reserved_index: u64 = verifier.reservedIndex().call().await?.try_into()?;
    let reserved_chain = u256_to_fr(verifier.reservedHashChain().call().await?);
    let proven = work.chain.index();

    if reserved_index > proven {
        let z_0 = vec![Fr::from(proven), work.chain.state(), work.tree.root()];
        let need = (reserved_index - proven) as usize;

        // Fetched AFTER the reserve mined, so head >= reserve block and the
        // window provably contains all `need` events.
        let latest = provider.get_block_number().await?;
        let events = fetch_transfers(provider, config.token, from_block + 1, latest).await?;
        if events.len() < need {
            return Err(format!(
                "need {need} epoch transfers from block {from_block}, found {}",
                events.len()
            )
            .into());
        }

        let mut witnesses = Vec::with_capacity(need);
        for &(_, to, value) in &events[..need] {
            witnesses.push(commit_transfer(&mut work, to, value)?);
        }
        if work.chain.state() != reserved_chain {
            return Err("hash chain diverged from reserved snapshot".into());
        }

        if witnesses.len() == 1 {
            let z_0 = [z_0[0], z_0[1], z_0[2]];
            let z_1 = [
                Fr::from(work.chain.index()),
                work.chain.state(),
                work.tree.root(),
            ];
            submit_single_update_root(
                provider,
                config,
                z_0,
                z_1,
                witnesses.into_iter().next().unwrap(),
            )
            .await?;
        } else {
            submit_update_root(provider, config, z_0, witnesses).await?;
        }
    }

    // ---- withdraws: fold only the not-yet-withdrawn suffix of proven deposits ----
    let Some(witnesses) = withdraw_witnesses(&work) else {
        return Ok(());
    };
    let recip = recipient(work.chain_id, work.exchange_addr, work.tweak);
    let withdrawn = verifier.totalWithdrawn(fr_to_u256(recip)).call().await?;
    let total = witnesses
        .iter()
        .fold(U256::ZERO, |acc, w| acc + fr_to_u256(w.value));
    if total <= withdrawn {
        debug!(stage = "withdraw", "nothing new beyond totalWithdrawn");
        return Ok(());
    }

    // Prior folds covered an index-contiguous prefix summing to exactly
    // `withdrawn` — cut the list there and fold only the new suffix.
    let mut prefix = U256::ZERO;
    let mut k = 0;
    while k < witnesses.len() && prefix < withdrawn {
        prefix += fr_to_u256(witnesses[k].value);
        k += 1;
    }
    if prefix != withdrawn {
        // Unreachable with the registered_from boundary: a pre-registration
        // deposit never enters the witness set.
        return Err(format!(
            "totalWithdrawn {withdrawn} misaligned with receipt prefix — deposit before registration?"
        )
        .into());
    }

    // The Nova decider needs >= 2 steps: pad a single-receipt batch with one
    // already-covered receipt on the left, shifting the fold's base by it.
    let pad = witnesses.len() - k == 1 && k > 0;
    let k = if pad { k - 1 } else { k };
    let z0_sum = prefix
        - if pad {
            fr_to_u256(witnesses[k].value)
        } else {
            U256::ZERO
        };

    let batch: Vec<WithdrawWitness> = witnesses[k..].to_vec();
    if batch.len() == 1 {
        // Reachable only when totalWithdrawn == 0, so the value IS the sum.
        submit_single_withdraw(provider, config, &work, batch.into_iter().next().unwrap()).await?;
    } else {
        submit_withdraws(provider, config, &work, batch, u256_to_fr(z0_sum)).await?;
    }

    Ok(())
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

/// Single-leaf epoch — Groth16 (the Nova decider needs >= 2 steps).
async fn submit_single_update_root(
    provider: &impl Provider,
    config: &Config,
    z_0: [Fr; 3],
    z_1: [Fr; 3],
    witness: RootTransitionWitness,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(stage = "commit", "proving one-leaf transition (Groth16)");
    let circuit = SingleRootTransitionCircuit { z_0, z_1, witness };
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
    let verifier = IVerifier::new(config.verifier, provider);
    let rc = send_and_confirm(|| {
        let c_ = verifier.clone();
        async move { c_.updateRootSingle(a, b, c, signals).send().await }
    })
    .await?;
    info!(stage = "commit", tx = %rc.transaction_hash, gas = rc.gas_used, "updateRootSingle confirmed");
    Ok(())
}

/// Multi-leaf epoch — Nova IVC folded per transfer + Groth16 decider.
async fn submit_update_root(
    provider: &impl Provider,
    config: &Config,
    z_0: Vec<Fr>,
    witnesses: Vec<RootTransitionWitness>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        stage = "commit",
        steps = witnesses.len(),
        "proving root transition (Nova + decider)"
    );
    let t = Instant::now();
    let calldata = prove_root_transition(RootTransitionCircuit::new(())?, z_0, witnesses)?;
    info!(stage = "commit", elapsed = ?t.elapsed(), "root proof done");
    let proof = decode_opaque_proof::<32>(&calldata);
    let verifier = IVerifier::new(config.verifier, provider);
    let rc = send_and_confirm(|| {
        let c_ = verifier.clone();
        async move { c_.updateRoot(proof).send().await }
    })
    .await?;
    info!(stage = "commit", tx = %rc.transaction_hash, gas = rc.gas_used, "updateRoot confirmed");
    Ok(())
}

/// First-ever withdraw of a recipient namespace (totalWithdrawn == 0): a
/// Groth16 proof over the single receipt whose value IS the lifetime sum.
async fn submit_single_withdraw(
    provider: &impl Provider,
    config: &Config,
    work: &State,
    witness: WithdrawWitness,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        stage = "withdraw",
        kind = "single",
        "proving single withdraw (Groth16)"
    );
    let recip = recipient(work.chain_id, work.exchange_addr, work.tweak);
    let circuit = SingleWithdrawCircuit {
        transfer_root: work.tree.root(),
        recipient: recip,
        index_with_offset: Fr::zero(),
        witness,
    };
    let value = circuit.witness.value;
    let (proof, _) = prove_single_withdraw(circuit)?;
    let (a, b, c) = pack_groth16(&proof);
    let signals: [U256; 3] = [
        fr_to_u256(work.tree.root()),
        fr_to_u256(recip),
        fr_to_u256(value),
    ];
    let verifier = IVerifier::new(config.verifier, provider);
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
    Ok(())
}

/// Batch withdraw — Nova IVC per receipt + Groth16 decider. The fold starts
/// at cumulative base `z0_sum` (the already-withdrawn prefix sum), so the
/// contract mints exactly Σ witnesses on top of totalWithdrawn.
async fn submit_withdraws(
    provider: &impl Provider,
    config: &Config,
    work: &State,
    witnesses: Vec<WithdrawWitness>,
    z0_sum: Fr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        stage = "withdraw",
        receipts = witnesses.len(),
        "proving batch withdraw (Nova + decider)"
    );
    let recip = recipient(work.chain_id, work.exchange_addr, work.tweak);
    let z_0 = vec![Fr::zero(), z0_sum, work.tree.root(), recip];
    let calldata = prove_withdraw(WithdrawCircuit::new(())?, z_0, witnesses)?;
    let proof = decode_opaque_proof::<34>(&calldata);
    let verifier = IVerifier::new(config.verifier, provider);
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
    Ok(())
}

/// Withdraw witnesses for every deposit in the working copy (all proven,
/// after the epoch above or by phase 1). Returns None when there are none.
fn withdraw_witnesses(s: &State) -> Option<Vec<WithdrawWitness>> {
    let mut receipts: Vec<(usize, G2, G2, Fq, Fr, Fr)> = Vec::new();
    for (addr, ds) in &s.deposits {
        let (Some(&pk), Some(&(sig_r, sig_z)), Some(&salt), Some(&from)) = (
            s.pubkey_by_addr.get(addr),
            s.sig_by_addr.get(addr),
            s.salt_by_addr.get(addr),
            s.registered_from.get(addr),
        ) else {
            continue;
        };
        for &(value, idx) in ds {
            if (idx as u64) < from {
                continue; // pre-registration deposit — burned, never folded
            }
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
        s.registered_from
            .insert(r.address, r.registered_from as u64);
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
    s.deposits.entry(to).or_default().push((value, index));
    Ok(())
}

/// Every Transfer in [from_block, to_block], ordered by (block, log index);
/// mints/burns excluded, matching the on-chain hash-chain rule.
async fn fetch_transfers(
    provider: &impl Provider,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<(u64, [u8; 20], Fr)>, Box<dyn std::error::Error>> {
    let mut logs = Vec::new(); // (block, log_index, to, value) until sorted
    let mut from = from_block;
    while from <= to_block {
        let to = (from + LOG_CHUNK - 1).min(to_block);
        let filter = Filter::new()
            .address(token)
            .event_signature(Transfer::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);
        for log in provider.get_logs(&filter).await? {
            let decoded = log.log_decode::<Transfer>()?;
            let d = decoded.data();
            if d.from == Address::ZERO || d.to == Address::ZERO {
                continue;
            }
            logs.push((
                log.block_number.ok_or("log without block number")?,
                log.log_index.ok_or("log without log index")?,
                d.to.into_array(),
                u256_to_fr(d.value),
            ));
        }
        from = to + 1;
    }
    logs.sort_by_key(|e| (e.0, e.1));
    Ok(logs.into_iter().map(|(b, _, t, v)| (b, t, v)).collect())
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
