use zetta::server::worker;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zetta=info".into()),
        )
        .init();

    loop {
        match worker::run().await {
            Ok(()) => break, // unreachable today; keeps the signature future-proof
            Err(e) => {
                tracing::error!(error = %e, "worker exited — restarting in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
