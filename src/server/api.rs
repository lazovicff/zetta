use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::{Affine as G2Affine, Projective as G2};

use crate::burn::{recipient, trim_to_160};
use crate::server::db::{Registration, fr_to_u256, unix_now};
use crate::server::state::State;
use crate::server::{AppState, parse_decimal_fq, parse_decimal_fr, parse_hex20};
use crate::zkp::poseidon3;

/// Claimable proven deposits for a pubkey: only deposits to addresses
/// registered under it, at indices at/after their registration boundary.
fn available_deposits(s: &State, pk_x: Fr) -> U256 {
    let mut total = U256::ZERO;
    for (addr, ds) in &s.deposits {
        let Some(pk) = s.pubkey_by_addr.get(addr) else {
            continue;
        };
        if pk.into_affine().x != pk_x {
            continue;
        }
        let from = s.registered_from.get(addr).copied().unwrap_or(u64::MAX);
        for &(value, idx) in ds {
            if idx as u64 >= from {
                total += fr_to_u256(value);
            }
        }
    }
    total
}

pub fn spawn_http_server(app: AppState, listener: tokio::net::TcpListener) {
    tokio::spawn(async move {
        let router = Router::new()
            .route("/health", get(health))
            .route("/recipient", get(current_recipient))
            .route("/register", post(register))
            .route("/deposits/:pubkey_x", get(deposits))
            .route("/deposits-by-user-id/:user_id", get(deposits_by_user_id))
            .route("/balance/:pubkey_x", get(balance))
            .route("/cards", post(order_card))
            .route("/next_card_nonce/:pubkey_x", get(next_card_nonce))
            .route("/withdraw", post(request_withdraw))
            .route("/next_withdraw_nonce/:pubkey_x", get(next_withdraw_nonce))
            .route("/status", get(status))
            .with_state(app);
        axum::serve(listener, router).await.unwrap();
    });
}

async fn next_card_nonce(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.next_card_nonce(pk_x).await {
        Ok(n) => Json(serde_json::json!({ "nonce": n })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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

    let (recipient, registered_from) = {
        let s = app.state.lock().unwrap();
        (
            recipient(s.chain_id, s.exchange_addr, s.tweak),
            s.chain.index(),
        )
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
        registered_from: registered_from as i64,
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
    s.registered_from
        .entry(addr)
        .and_modify(|f| *f = (*f).min(registered_from))
        .or_insert(registered_from);

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
    sig_r: (String, String),
    sig_z: String,
    nonce: i64,
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

    let (available, fee_bps) = {
        let s = app.state.lock().unwrap();
        (available_deposits(&s, pk_x), s.card_fee_bps)
    };

    let amount_u256 = fr_to_u256(amount);
    let fee = amount_u256 * U256::from(fee_bps) / U256::from(10_000u64);

    // 1. verify sig + reserve funds atomically (status 'pending')
    let provider_ref = format!("stub-{amount_u256}-{}", unix_now());
    let new_spent = app
        .db
        .try_card_order(
            reg.pubkey_x,
            reg.pubkey_y,
            amount,
            req.nonce,
            fee,
            available,
            r,
            z,
            "stub",
            &provider_ref,
        )
        .await?;

    // 2. provider call — stub always succeeds; real provider goes here
    match Ok::<_, String>(()) {
        Ok(()) => {
            app.db
                .settle_card_order(&provider_ref, "succeeded", None)
                .await?;
            Ok(serde_json::json!({
                "amount": amount_u256.to_string(),
                "fee": fee.to_string(),
                "provider": "stub",
                "provider_ref": provider_ref,
                "lifetime_spent": new_spent.to_string(),
            }))
        }
        Err(e) => {
            let msg = e.to_string();
            app.db
                .settle_card_order(&provider_ref, "failed", Some(&msg))
                .await?;
            Err(format!("card provider failed: {msg}"))
        }
    }
}

#[derive(serde::Deserialize)]
struct WithdrawReq {
    pubkey_x: String,    // decimal
    amount: String,      // decimal token units (debited; payout = amount - fee)
    destination: String, // 0x + 40 hex
    nonce: i64,          // per-user sequence; signs over it, single-use
    sig_r: (String, String),
    sig_z: String,
}

async fn next_withdraw_nonce(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.next_withdraw_nonce(pk_x).await {
        Ok(n) => Json(serde_json::json!({ "nonce": n })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn request_withdraw(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<WithdrawReq>,
) -> impl IntoResponse {
    match withdraw_inner(&app, req).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn withdraw_inner(app: &AppState, req: WithdrawReq) -> Result<serde_json::Value, String> {
    let pk_x = parse_decimal_fr(&req.pubkey_x)?;
    let amount = parse_decimal_fr(&req.amount)?;
    let destination = parse_hex20(&req.destination)?;
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

    let (available, fee_bps) = {
        let s = app.state.lock().unwrap();
        (available_deposits(&s, pk_x), s.withdraw_fee_bps)
    };

    let amount_u256 = fr_to_u256(amount);
    let fee = amount_u256 * U256::from(fee_bps) / U256::from(10_000u64);
    let payout = amount_u256 - fee; // try_withdraw rejects fee > amount

    // Verify sig + reserve atomically (status 'pending'); the worker pays out.
    let ref_ = format!("wd-{amount_u256}-{}", unix_now());
    app.db
        .try_withdraw(
            reg.pubkey_x,
            reg.pubkey_y,
            amount,
            req.nonce,
            fee,
            available,
            destination,
            r,
            z,
            &ref_,
        )
        .await?;

    Ok(serde_json::json!({
        "ref": ref_,
        "amount": amount_u256.to_string(),
        "fee": fee.to_string(),
        "payout": payout.to_string(),
        "status": "pending",
    }))
}

async fn status(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({
        "index": s.chain.index(),
        "committed_index": s.committed_index,
        "queued": s.uncommitted_leaves.len(),
        "root": s.tree.root().to_string(),
        "deposits": s.deposits.len(),
        "registered": s.pubkey_by_addr.len(),
    }))
    .into_response()
}

/// Claimable deposits (tree index >= registration boundary) for every address
/// whose registered pubkey is `pk_x`.
fn deposit_rows(s: &State, pk_x: Fr) -> Vec<serde_json::Value> {
    s.deposits
        .iter()
        .filter(|(addr, _)| s.pubkey_by_addr.get(*addr).map(|p| p.into_affine().x) == Some(pk_x))
        .flat_map(|(addr, ds)| {
            let from = s.registered_from.get(addr).copied().unwrap_or(u64::MAX);
            ds.iter().filter_map(move |(value, idx)| {
                (*idx as u64 >= from).then(|| {
                    serde_json::json!({
                        "address": format!("0x{}", hex::encode(addr)),
                        "value": value.to_string(),
                        "tree_index": idx,
                    })
                })
            })
        })
        .collect()
}

async fn deposits(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({ "deposits": deposit_rows(&s, pk_x) })).into_response()
}

async fn deposits_by_user_id(
    AxumState(app): AxumState<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let pk_x = match app.db.pubkey_by_user_id(&user_id).await {
        Ok(Some(pk)) => pk,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown user id").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({ "deposits": deposit_rows(&s, pk_x) })).into_response()
}
