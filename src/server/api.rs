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
use crate::server::{AppState, parse_decimal_fq, parse_decimal_fr, parse_hex20};
use crate::zkp::{poseidon2, poseidon3};

pub fn spawn_http_server(app: AppState, port: u16) {
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
        "committed_index": s.committed_index,
        "queued": s.uncommitted_leaves.len(),
        "root": s.tree.root().to_string(),
        "deposits": s.deposits.len(),
        "registered": s.pubkey_by_addr.len(),
    }))
    .into_response()
}

async fn deposits(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    let list: Vec<_> = s
        .deposits
        .iter()
        .flat_map(|(addr, ds)| {
            ds.iter().map(move |(value, idx)| {
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
