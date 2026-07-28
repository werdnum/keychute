//! Grants: durable capabilities with atomic use-accounting and idempotent
//! replay. See docs/IMPLEMENTATION.md §Atomicity requirements.

use crate::audit::{insert_audit, AuditEvent};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Where the credential is about to be sent (proxy leg): recorded on the
/// write-ahead audit row. The read path has no target and passes `None`.
#[derive(Debug, Clone)]
pub struct AuditTarget {
    pub method: String,
    pub origin: String,
    pub path: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GrantRow {
    pub id: Uuid,
    pub request_id: Uuid,
    pub client_name: String,
    pub secret_name: String,
    pub mechanism: String,
    pub constraints: serde_json::Value,
    pub not_after: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub revoked: bool,
    pub passthrough_ciphertext: Option<Vec<u8>>,
    pub passthrough_nonce: Option<Vec<u8>>,
    pub passthrough_wrapped_dek: Option<Vec<u8>>,
    pub passthrough_ephemeral: bool,
    pub created_at: DateTime<Utc>,
}

/// Outcome of one atomic grant-use attempt.
#[derive(Debug)]
pub enum GrantUse {
    /// No grant with that id.
    NotFound,
    /// Revoked, or past `not_after`. (Replay revalidates this too.)
    ExpiredOrRevoked,
    /// Live grant but no uses left — or an idempotency key was reused after
    /// its replay window closed (the key is burned; it can never be a fresh
    /// use again).
    Exhausted,
    /// Same idempotency key within the replay window: return the pinned
    /// payload without incrementing `use_count`.
    Replay {
        grant: GrantRow,
        secret_version_id: Option<Uuid>,
        passthrough: bool,
    },
    /// Use accounted: `use_count` incremented, replay state and the
    /// write-ahead audit row committed in the same transaction.
    FirstUse { grant: GrantRow },
}

/// Atomically account one grant use.
///
/// In a single transaction: lock the grant row (`FOR UPDATE`), revalidate
/// revocation/expiry, check `grant_reads` for a same-key replay, then
/// conditionally increment `use_count`, record replay state, and commit the
/// write-ahead audit row (`audit_kind`: release-attempt or proxy-attempt).
///
/// `secret_version_id` is the payload id the caller resolved BEFORE calling
/// (current secret version, or the grant id for passthrough) — stable within
/// the transaction, and pinned into `grant_reads` so replays release exactly
/// that version. `idem_key` is `None` for proxy calls (no replay semantics).
pub async fn begin_grant_use(
    db: &PgPool,
    grant_id: Uuid,
    idem_key: Option<&str>,
    secret_version_id: Option<Uuid>,
    audit_kind: &'static str,
    replay_window_seconds: i64,
    target: Option<&AuditTarget>,
) -> anyhow::Result<GrantUse> {
    let mut tx = db.begin().await?;
    let grant = sqlx::query_as::<_, GrantRow>("SELECT * FROM grants WHERE id = $1 FOR UPDATE")
        .bind(grant_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(grant) = grant else {
        return Ok(GrantUse::NotFound);
    };
    // Revocation/expiry evaluated in SQL (DB clock), inside the row lock.
    // This gates both the replay path and the fresh-use path.
    let live: bool =
        sqlx::query_scalar("SELECT NOT revoked AND now() < not_after FROM grants WHERE id = $1")
            .bind(grant_id)
            .fetch_one(&mut *tx)
            .await?;
    if !live {
        return Ok(GrantUse::ExpiredOrRevoked);
    }

    if let Some(key) = idem_key {
        // Replay-window check as a DB-time predicate: `in_window` is computed
        // by Postgres against `first_read_at`, never the process clock.
        let prior: Option<(Option<Uuid>, bool, bool)> = sqlx::query_as(
            "SELECT secret_version_id, passthrough, \
                    first_read_at > now() - make_interval(secs => $3::double precision) \
             FROM grant_reads WHERE grant_id = $1 AND idem_key = $2",
        )
        .bind(grant_id)
        .bind(key)
        .bind(replay_window_seconds as f64)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((pinned_version, passthrough, in_window)) = prior {
            if in_window {
                insert_audit(
                    &mut *tx,
                    &AuditEvent {
                        kind: audit_kind,
                        request_id: Some(grant.request_id),
                        grant_id: Some(grant_id),
                        client_name: Some(grant.client_name.clone()),
                        secret_name: Some(grant.secret_name.clone()),
                        secret_version_id: pinned_version,
                        method: target.map(|t| t.method.clone()),
                        origin: target.map(|t| t.origin.clone()),
                        path: target.map(|t| t.path.clone()),
                        detail: Some(serde_json::json!({ "replay": true })),
                        ..Default::default()
                    },
                )
                .await?;
                tx.commit().await?;
                return Ok(GrantUse::Replay {
                    grant,
                    secret_version_id: pinned_version,
                    passthrough,
                });
            }
            // Key seen before but the replay window has closed: it can no
            // longer be replayed, and (grant_id, idem_key) is unique, so it
            // cannot become a fresh use either.
            return Ok(GrantUse::Exhausted);
        }
    }

    let updated = sqlx::query_as::<_, GrantRow>(
        "UPDATE grants SET use_count = use_count + 1 \
         WHERE id = $1 AND NOT revoked AND now() < not_after \
           AND (max_uses IS NULL OR use_count < max_uses) \
         RETURNING *",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(grant) = updated else {
        return Ok(GrantUse::Exhausted);
    };
    if let Some(key) = idem_key {
        sqlx::query(
            "INSERT INTO grant_reads (grant_id, idem_key, secret_version_id, passthrough) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(grant_id)
        .bind(key)
        .bind(secret_version_id)
        .bind(grant.passthrough_ciphertext.is_some())
        .execute(&mut *tx)
        .await?;
    }
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: audit_kind,
            request_id: Some(grant.request_id),
            grant_id: Some(grant_id),
            client_name: Some(grant.client_name.clone()),
            secret_name: Some(grant.secret_name.clone()),
            secret_version_id,
            method: target.map(|t| t.method.clone()),
            origin: target.map(|t| t.origin.clone()),
            path: target.map(|t| t.path.clone()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(GrantUse::FirstUse { grant })
}

pub async fn get_grant(db: &PgPool, id: Uuid) -> anyhow::Result<Option<GrantRow>> {
    Ok(
        sqlx::query_as::<_, GrantRow>("SELECT * FROM grants WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn list_grants(db: &PgPool) -> anyhow::Result<Vec<GrantRow>> {
    Ok(
        sqlx::query_as::<_, GrantRow>("SELECT * FROM grants ORDER BY created_at DESC")
            .fetch_all(db)
            .await?,
    )
}

/// Revoke a grant and purge any passthrough payload, with an audit row in the
/// same transaction. Returns false if the grant was already revoked or absent.
pub async fn revoke_grant(db: &PgPool, grant_id: Uuid, actor: &str) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "UPDATE grants SET revoked = true, \
             passthrough_ciphertext = NULL, passthrough_nonce = NULL, \
             passthrough_wrapped_dek = NULL \
         WHERE id = $1 AND NOT revoked \
         RETURNING request_id, client_name, secret_name",
    )
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((request_id, client_name, secret_name)) = row else {
        return Ok(false);
    };
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: crate::audit::kinds::GRANT_REVOKED,
            request_id: Some(request_id),
            grant_id: Some(grant_id),
            client_name: Some(client_name),
            secret_name: Some(secret_name),
            actor: Some(actor.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Null out the passthrough payload of one grant (e.g. after its replay
/// window closes).
pub async fn purge_passthrough(db: &PgPool, grant_id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE grants SET passthrough_ciphertext = NULL, passthrough_nonce = NULL, \
             passthrough_wrapped_dek = NULL \
         WHERE id = $1",
    )
    .bind(grant_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Sweep: purge passthrough payloads from grants that are revoked, expired,
/// or fully consumed with no replay still open (no read newer than the replay
/// window). Returns rows purged.
pub async fn sweep_purge_passthroughs(
    db: &PgPool,
    now: DateTime<Utc>,
    replay_window_seconds: i64,
) -> anyhow::Result<u64> {
    let window_start = now - Duration::seconds(replay_window_seconds);
    let res = sqlx::query(
        "UPDATE grants g SET passthrough_ciphertext = NULL, passthrough_nonce = NULL, \
             passthrough_wrapped_dek = NULL \
         WHERE g.passthrough_ciphertext IS NOT NULL \
           AND (g.revoked \
                OR g.not_after < $1 \
                OR (g.max_uses IS NOT NULL AND g.use_count >= g.max_uses \
                    AND NOT EXISTS (SELECT 1 FROM grant_reads r \
                                    WHERE r.grant_id = g.id AND r.first_read_at > $2)))",
    )
    .bind(now)
    .bind(window_start)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}
