use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use std::sync::{Arc, Mutex};
use zetta::server::worker::catch_up;

use zetta::config::Config;
use zetta::server::db::Db;
use zetta::server::state::State;
use zetta::server::{AppState, SharedState, api, worker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zetta=info".into()),
        )
        .init();

    // ---- boot once: config, params, signer, state, db ----
    tracing::info!(stage = "boot", "loading config");
    let config = Config::from_env()?;

    tracing::info!(stage = "boot", "loading proving params");
    let t = std::time::Instant::now();
    zetta::zkp::cached_root_params()?;
    zetta::zkp::cached_withdraw_params()?;
    zetta::zkp::cached_single_root_params()?;
    zetta::zkp::cached_single_withdraw_params()?;
    tracing::info!(stage = "boot", elapsed = ?t.elapsed(), "proving params loaded");
    // (if you haven't applied the param refactor, use root_params()/withdraw_params()/… here)

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
    tracing::info!(stage = "boot", "database connected");

    worker::hydrate_registrations(&state, &db).await?;
    worker::log_recipient(&state);

    // ---- HTTP API: bind fatal, spawn once, never restarted ----
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port))
        .await
        .map_err(|e| {
            format!(
                "bind :{} failed: {e} — stale zetta process? kill it: kill $(lsof -ti :{})",
                config.port, config.port
            )
        })?;
    api::spawn_http_server(
        AppState {
            state: state.clone(),
            db: db.clone(),
        },
        listener,
    );
    tracing::info!(stage = "boot", port = config.port, "HTTP server bound");

    // ---- initial chain sync, once ----
    let mut last_block = catch_up(&state, &provider, &config).await?;
    tracing::info!(stage = "catchup", last_block, "catch-up complete");

    // ---- worker retry loop: resumes polling with the SAME state ----
    loop {
        match worker::run(&state, &provider, &config, &db, &mut last_block).await {
            Ok(()) => continue, // unreachable today
            Err(e) => {
                tracing::error!(error = %e, "worker exited — restarting in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
