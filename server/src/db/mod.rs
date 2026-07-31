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

/// Seals a payload inside the writing transaction. Addendum #19: the active
/// KEK must be READ under the shared lock, not before it — a caller that
/// sealed first could have that KEK retired between the seal and the commit
/// (retirement's zero-reference check would run in the gap and see nothing),
/// leaving the row permanently undecryptable. Store functions that persist a
/// wrapped DEK therefore take one of these rather than pre-sealed bytes.
pub type SealFn<'a> =
    Box<dyn FnOnce() -> Result<crate::crypto::Sealed, crate::crypto::CryptoError> + Send + 'a>;

/// Addendum #19: transactions inserting a wrapped DEK take the shared side of
/// the KEK-retirement advisory lock, so KEK retirement (exclusive side) can
/// verify no new references appear while it checks. Take it BEFORE sealing
/// (see [`SealFn`]).
pub(crate) async fn take_kek_shared_lock(tx: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtext('keychute-kek'))")
        .execute(tx)
        .await?;
    Ok(())
}

/// Serializes stored-secret DELETION against stored-backed GRANT CREATION for
/// the same secret name. Grants reference a secret by name with no foreign
/// key, so without this a grant inserted after the delete's `UPDATE ... SET
/// revoked` took its snapshot commits unrevoked against a secret whose
/// ciphertext is already gone — an apparently live grant that can only ever
/// return `payload-lost`.
///
/// Grant creators take the SHARED side before inserting a non-passthrough
/// grant, and re-check the secret still exists once they hold it (holding the
/// lock is not enough on its own: a delete that got there first has already
/// committed, and the approval must then fail rather than mint a dud grant).
/// [`crate::db::ui_ext::delete_secret_audited`] takes the exclusive side.
///
/// Lock ORDER, everywhere it is taken: this one first, before the KEK lock and
/// before any per-client lock. Nothing may take it after those, or the two
/// orders could deadlock against each other.
pub(crate) async fn take_secret_shared_lock(
    tx: &mut sqlx::PgConnection,
    secret_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtext('keychute-secret'), hashtext($1))")
        .bind(secret_name)
        .execute(tx)
        .await?;
    Ok(())
}

/// Exclusive side of [`take_secret_shared_lock`] — deletion's half.
pub(crate) async fn take_secret_exclusive_lock(
    tx: &mut sqlx::PgConnection,
    secret_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keychute-secret'), hashtext($1))")
        .bind(secret_name)
        .execute(tx)
        .await?;
    Ok(())
}

/// True when a secret of this name exists — read inside a transaction that
/// already holds the secret lock, by grant creators checking that a deletion
/// did not just win the race.
pub(crate) async fn secret_name_exists(
    tx: &mut sqlx::PgConnection,
    secret_name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM secrets WHERE name = $1)")
        .bind(secret_name)
        .fetch_one(tx)
        .await
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
/// Counts `secret_versions.kek_id` and `access_requests.context_kek_id` —
/// every place a keyset-wrapped DEK is stored. Grant passthrough payloads are
/// intentionally not counted: they are wrapped under the process-local
/// ephemeral KEK, which is not in the keyset and dies with the process
/// ([`PassthroughPayload`]), so no `kek_id` here can ever be one of theirs.
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

/// The database clock. Persisted deadlines (request expiry, grant
/// `not_after`) are derived from this rather than the process clock: every
/// predicate that later enforces them runs on SQL `now()`, so a skewed server
/// clock must not be able to lengthen (or shorten) a TTL as the database
/// measures it.
pub async fn db_now(db: &sqlx::PgPool) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    Ok(sqlx::query_scalar("SELECT now()").fetch_one(db).await?)
}

pub use clients::{get_client_by_name, list_clients, reconcile_clients, ClientRow};
pub use grants::{
    begin_grant_use, get_grant, get_grant_for_request, list_grants, purge_passthrough,
    revoke_grant, sweep_purge_passthroughs, AuditTarget, GrantRow, GrantUse,
};
pub use policies::{
    count_policies, delete_policy, insert_policy, list_policies, NewPolicy, PolicyRow,
};
pub use requests::{
    count_pending, count_pending_for_client, expire_stale, get_request, increment_push_attempts,
    insert_access_request, list_notify_only_needing_push, list_pending, list_pending_needing_push,
    mark_push_delivered, purge_request_context, resolve_approve, resolve_deny, AccessRequestRow,
    GrantParams, InsertedRequest, NewAccessRequest, PassthroughPayload,
};
pub use secrets::{
    client_deposit_origin, count_secrets, create_secret, create_secret_from_client,
    get_secret_by_name, get_secret_version, get_secret_version_by_id, get_tags_for_secret,
    insert_secret_version, list_secrets, list_unvetted_secret_names, mark_secret_vetted,
    set_secret_tags, DepositOutcome, DepositRate, SecretRow, SecretVersionRow,
};
