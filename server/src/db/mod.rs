//! Store layer: all SQL lives here. Contract in docs/IMPLEMENTATION.md §DB.
//!
//! Conventions:
//! - Runtime queries only (`sqlx::query` / `query_as` / `query_scalar` with
//!   `.bind()`); no compile-time `query!` macros.
//! - Multi-statement invariants (approve, grant use, version append) run in
//!   explicit transactions; audit rows join the same transaction.
//! - Row structs mirror columns 1:1; higher layers convert to domain types.

pub mod api_ext;
pub mod clients;
pub mod grants;
pub mod policies;
pub mod requests;
pub mod secrets;
pub mod ui_ext;

#[cfg(test)]
mod tests;

/// Addendum #19: transactions inserting a wrapped DEK take the shared side of
/// the KEK-retirement advisory lock, so KEK retirement (exclusive side) can
/// verify no new references appear while it checks.
pub(crate) async fn take_kek_shared_lock(tx: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtext('keychute-kek'))")
        .execute(tx)
        .await?;
    Ok(())
}

/// Addendum #19 (`verify_no_references`): true when nothing still references
/// `kek_id`, i.e. it is safe to retire. Takes the EXCLUSIVE form of the KEK
/// advisory lock for the check's transaction, so it serializes against every
/// in-flight transaction inserting a wrapped DEK (those hold the shared form):
/// a writer that already sealed under `kek_id` has either committed — and is
/// counted here — or queues behind this lock and commits only after the check,
/// under whatever KEK is active by then. Without the lock, an in-flight insert
/// could land just after a zero count and become permanently undecryptable
/// once the operator removes the KEK.
///
/// Counts `secret_versions.kek_id` and `access_requests.context_kek_id`.
/// Grant passthrough payloads carry no kek_id column: durable passthroughs are
/// wrapped under the active KEK and short-lived, and ephemeral ones die with
/// the process, so they are intentionally not counted here.
pub async fn verify_no_references(db: &sqlx::PgPool, kek_id: &str) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keychute-kek'))")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM secret_versions WHERE kek_id = $1) \
              + (SELECT count(*) FROM access_requests WHERE context_kek_id = $1)",
    )
    .bind(kek_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(count == 0)
}

pub use clients::{get_client_by_name, list_clients, reconcile_clients, ClientRow};
pub use grants::{
    begin_grant_use, get_grant, list_grants, purge_passthrough, revoke_grant,
    sweep_purge_passthroughs, AuditTarget, GrantRow, GrantUse,
};
pub use policies::{delete_policy, insert_policy, list_policies, NewPolicy, PolicyRow};
pub use requests::{
    count_pending_for_client, expire_stale, get_request, increment_push_attempts,
    insert_access_request, list_pending, list_pending_needing_push, mark_push_delivered,
    purge_request_context, resolve_approve, resolve_deny, AccessRequestRow, GrantParams,
    InsertedRequest, NewAccessRequest, PassthroughPayload,
};
pub use secrets::{
    create_secret, get_secret_by_name, get_secret_version, get_secret_version_by_id,
    get_tags_for_secret, insert_secret_version, list_secrets, set_secret_tags, SecretRow,
    SecretVersionRow,
};
