//! Keychute server library. See docs/DESIGN.md and docs/IMPLEMENTATION.md.

pub mod api;
pub mod audit;
pub mod authn;
pub mod config;
pub mod crypto;
pub mod db;
pub mod notify;
pub mod policy;
pub mod proxy;
pub mod state;
pub mod ui;

use anyhow::Context;

/// Run the server until shutdown.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let state = state::AppState::init(config)
        .await
        .context("initializing")?;
    let app = api::router(state.clone()).merge(ui::router(state.clone()));

    // Background sweeps: push outbox retry + request expiry + purge.
    notify::spawn_sweeper(state.clone());

    let addr: std::net::SocketAddr = state.config.listen_addr.parse()?;
    tracing::info!(%addr, tls = state.config.tls.is_some(), "keychute-server listening");
    match &state.config.tls {
        Some(tls) => {
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                    .await
                    .context("loading TLS cert/key")?;
            axum_server::bind_rustls(addr, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
        None => {
            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await?;
        }
    }
    Ok(())
}
