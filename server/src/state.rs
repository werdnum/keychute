//! Shared application state.

use crate::config::Config;
use crate::crypto::{EphemeralKek, Keyset};
use crate::notify::Notifier;
use anyhow::Context;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

pub struct Inner {
    pub config: Config,
    pub db: sqlx::PgPool,
    pub keyset: Keyset,
    pub ephemeral_kek: EphemeralKek,
    pub notifier: Arc<dyn Notifier>,
    /// Wakes wait-endpoint pollers when a request resolves.
    pub resolve_notify: tokio::sync::Notify,
    /// Per-client concurrency accounting (waits and proxy streams).
    pub wait_counts: Mutex<HashMap<String, usize>>,
    pub proxy_counts: Mutex<HashMap<String, usize>>,
    /// Outbound HTTP client for the proxy leg (no redirects).
    pub upstream: reqwest::Client,
    /// Total live wait connections (diagnostics).
    pub total_waits: AtomicUsize,
}

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub async fn init(config: Config) -> anyhow::Result<AppState> {
        let keyset = Keyset::load(&config.kek_file)?;
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(config.database_url())
            .await?;
        sqlx::migrate!("../migrations").run(&db).await?;
        crate::db::reconcile_clients(&db, &config.clients).await?;

        let notifier = crate::notify::build_notifier(&config)?;
        let mut upstream_builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10));
        // Internal-CA trust for upstream origins (config `upstream_ca_path`).
        if let Some(ca_path) = &config.upstream_ca_path {
            let pem = std::fs::read(ca_path)
                .with_context(|| format!("reading upstream_ca_path {}", ca_path.display()))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .context("parsing upstream_ca_path PEM bundle")?
            {
                upstream_builder = upstream_builder.add_root_certificate(cert);
            }
        }
        let upstream = upstream_builder.build()?;

        Ok(AppState(Arc::new(Inner {
            config,
            db,
            keyset,
            ephemeral_kek: EphemeralKek::generate(),
            notifier,
            resolve_notify: tokio::sync::Notify::new(),
            wait_counts: Mutex::new(HashMap::new()),
            proxy_counts: Mutex::new(HashMap::new()),
            upstream,
            total_waits: AtomicUsize::new(0),
        })))
    }
}

/// RAII guard for per-client concurrency slots.
pub struct SlotGuard {
    map: Arc<Inner>,
    client: String,
    which: SlotKind,
}

#[derive(Clone, Copy)]
pub enum SlotKind {
    Wait,
    Proxy,
}

impl AppState {
    /// Try to take a slot; None if the per-client cap is reached.
    pub fn try_take_slot(&self, client: &str, which: SlotKind) -> Option<SlotGuard> {
        let (map, cap) = match which {
            SlotKind::Wait => (&self.wait_counts, self.config.limits.max_waits_per_client),
            SlotKind::Proxy => (
                &self.proxy_counts,
                self.config.limits.max_proxy_streams_per_client,
            ),
        };
        let mut counts = map.lock().unwrap();
        let n = counts.entry(client.to_string()).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(SlotGuard {
            map: self.0.clone(),
            client: client.to_string(),
            which,
        })
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let map = match self.which {
            SlotKind::Wait => &self.map.wait_counts,
            SlotKind::Proxy => &self.map.proxy_counts,
        };
        let mut counts = map.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.client) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.client);
            }
        }
    }
}
