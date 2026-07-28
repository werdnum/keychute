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
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Resolves on SIGTERM (Kubernetes rollout / `docker stop`) or Ctrl-C.
///
/// SIGKILL is deliberately absent because it cannot be caught: the e2e harness
/// kills the server with `Child::kill()` (SIGKILL), so its restart tests —
/// including `restart_loses_passthrough_and_fails_closed` — keep their exact
/// meaning, with no drain and no chance to persist the ephemeral KEK.
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            // Handler could not be installed; never fire this branch.
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "installing SIGTERM handler failed");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}

/// Run the server until shutdown.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let state = state::AppState::init(config)
        .await
        .context("initializing")?;
    let app = api::router(state.clone()).merge(ui::router(state.clone()));

    // Background sweeps: push outbox retry + request expiry + purge.
    let (sweeper_stop, sweeper_stopped) = tokio::sync::watch::channel(false);
    let sweeper = notify::spawn_sweeper(state.clone(), sweeper_stopped);

    let addr: std::net::SocketAddr = state.config.listen_addr.parse()?;
    let drain = Duration::from_secs(state.config.limits.drain_seconds);
    tracing::info!(
        %addr,
        tls = state.config.tls.is_some(),
        drain_seconds = drain.as_secs(),
        "keychute-server listening"
    );

    // One handle drives graceful shutdown for BOTH the TLS and plain paths: it
    // stops accepting new connections and gives in-flight responses `drain` to
    // finish before the remainder is closed.
    let handle = axum_server::Handle::new();
    let drain_started: std::sync::Arc<OnceLock<Instant>> = std::sync::Arc::new(OnceLock::new());
    let signal_task = tokio::spawn({
        let handle = handle.clone();
        let drain_started = drain_started.clone();
        async move {
            shutdown_signal().await;
            let _ = drain_started.set(Instant::now());
            tracing::info!(
                drain_seconds = drain.as_secs(),
                "shutdown signal received; draining in-flight requests"
            );
            // Stop the sweeper too: its next tick would only do work that is
            // about to be redone by the replacement process.
            let _ = sweeper_stop.send(true);
            handle.graceful_shutdown(Some(drain));
        }
    });

    let serve_result = match &state.config.tls {
        Some(tls) => {
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                    .await
                    .context("loading TLS cert/key")?;
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        None => {
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };

    match drain_started.get() {
        Some(started) if started.elapsed() >= drain => tracing::warn!(
            drain_seconds = drain.as_secs(),
            "drain deadline reached; remaining in-flight requests were cut off"
        ),
        Some(started) => tracing::info!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "in-flight requests drained; shutting down"
        ),
        // Server returned without a shutdown signal (bind/accept failure).
        None => signal_task.abort(),
    }
    // The sweeper was told to stop; do not let a sweep that is mid-push hold
    // the process open indefinitely.
    if tokio::time::timeout(Duration::from_secs(2), sweeper)
        .await
        .is_err()
    {
        tracing::warn!("background sweeper still busy at exit; abandoning it");
    }
    serve_result?;
    Ok(())
}
