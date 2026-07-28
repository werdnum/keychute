//! Store layer: all SQL lives here. Contract in docs/IMPLEMENTATION.md §DB.
//! STUB — implemented by the db task.

use crate::config::ClientConfig;
use sqlx::PgPool;

/// Reconcile the `clients` table from declarative config at startup:
/// upsert by name, disable rows not present in config.
pub async fn reconcile_clients(_db: &PgPool, _clients: &[ClientConfig]) -> anyhow::Result<()> {
    unimplemented!("db task")
}
