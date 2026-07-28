//! Notifier trait, Pushover impl, outbox sweep. STUB — implemented by the UI/notify task.

use crate::config::Config;
use crate::state::AppState;
use std::sync::Arc;

pub struct Notification {
    pub title: String,
    /// Server-vocabulary only: client name, secret name, tier, mechanism.
    pub message: String,
    pub url: Option<String>,
    pub url_title: Option<String>,
}

#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, n: &Notification) -> anyhow::Result<()>;
}

/// No-op notifier used when pushover is not configured.
pub struct NullNotifier;

#[async_trait::async_trait]
impl Notifier for NullNotifier {
    async fn send(&self, _n: &Notification) -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn build_notifier(_config: &Config) -> Arc<dyn Notifier> {
    Arc::new(NullNotifier)
}

/// Spawn background sweeps: push retry for pending requests without recorded
/// delivery, request expiry, passthrough purge.
pub fn spawn_sweeper(_state: AppState) {
    // implemented by notify task
}
