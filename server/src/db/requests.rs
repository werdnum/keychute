//! Access requests: idempotent creation, resolution, expiry, push outbox.

use crate::audit::{insert_audit, kinds, AuditEvent};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccessRequestRow {
    pub id: Uuid,
    pub client_name: String,
    pub secret_name: String,
    pub mechanism: String,
    pub constraints: serde_json::Value,
    pub context_ciphertext: Option<Vec<u8>>,
    pub context_nonce: Option<Vec<u8>>,
    pub context_wrapped_dek: Option<Vec<u8>>,
    pub context_kek_id: Option<String>,
    pub state: String,
    /// Expiry of the standing policy row that matched at creation time, when
    /// one did. A later human approval caps the grant at it (migration 0005).
    pub policy_not_after: Option<DateTime<Utc>>,
    pub deny_reason: Option<String>,
    pub resolved_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub push_delivered_at: Option<DateTime<Utc>>,
    pub push_attempts: i32,
    pub idem_client: String,
    pub idem_key: String,
    pub idem_mac: Vec<u8>,
}

/// Insert parameters for a new access request. `idem_mac` is the keyed MAC of
/// the normalized payload (computed by the caller with the keyset MAC key).
///
/// The encrypted client context is NOT part of this struct: it is sealed by a
/// [`super::SealFn`] the insert runs inside its own transaction, under the KEK
/// shared lock (addendum #19).
#[derive(Debug, Clone)]
pub struct NewAccessRequest {
    pub client_name: String,
    pub secret_name: String,
    pub mechanism: String,
    pub constraints: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    /// Cap inherited from the matching standing policy row (see
    /// [`AccessRequestRow::policy_not_after`]).
    pub policy_not_after: Option<DateTime<Utc>>,
    pub idem_client: String,
    pub idem_key: String,
    pub idem_mac: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InsertedRequest {
    pub row: AccessRequestRow,
    /// False when an existing row for (idem_client, idem_key) was returned.
    /// The caller decides 200-vs-409 by comparing `row.idem_mac` with the
    /// MAC of the incoming payload.
    pub created: bool,
}

/// Idempotent insert: `ON CONFLICT (idem_client, idem_key) DO NOTHING`, then
/// select the surviving row. `seal_context` is `Some` when the client sent a
/// context to store: the transaction takes the KEK shared advisory lock and
/// only then seals (addendum #19), so the KEK the seal picks cannot be retired
/// before this row commits.
pub async fn insert_access_request(
    db: &PgPool,
    req: &NewAccessRequest,
    seal_context: Option<super::SealFn<'_>>,
) -> anyhow::Result<InsertedRequest> {
    let mut tx = db.begin().await?;
    let context = match seal_context {
        Some(seal) => {
            super::take_kek_shared_lock(&mut tx).await?;
            Some(seal().map_err(|e| anyhow::anyhow!("sealing request context: {e}"))?)
        }
        None => None,
    };
    let inserted = sqlx::query_as::<_, AccessRequestRow>(
        "INSERT INTO access_requests \
         (client_name, secret_name, mechanism, constraints, \
          context_ciphertext, context_nonce, context_wrapped_dek, context_kek_id, \
          expires_at, policy_not_after, idem_client, idem_key, idem_mac) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (idem_client, idem_key) DO NOTHING \
         RETURNING *",
    )
    .bind(&req.client_name)
    .bind(&req.secret_name)
    .bind(&req.mechanism)
    .bind(&req.constraints)
    .bind(context.as_ref().map(|s| s.ciphertext.as_slice()))
    .bind(context.as_ref().map(|s| s.nonce.as_slice()))
    .bind(context.as_ref().map(|s| s.wrapped_dek.as_slice()))
    .bind(context.as_ref().map(|s| s.kek_id.as_str()))
    .bind(req.expires_at)
    .bind(req.policy_not_after)
    .bind(&req.idem_client)
    .bind(&req.idem_key)
    .bind(&req.idem_mac)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = inserted {
        tx.commit().await?;
        return Ok(InsertedRequest { row, created: true });
    }
    tx.rollback().await?;
    let row = sqlx::query_as::<_, AccessRequestRow>(
        "SELECT * FROM access_requests WHERE idem_client = $1 AND idem_key = $2",
    )
    .bind(&req.idem_client)
    .bind(&req.idem_key)
    .fetch_one(db)
    .await?;
    Ok(InsertedRequest {
        row,
        created: false,
    })
}

pub async fn count_pending_for_client(db: &PgPool, client_name: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM access_requests WHERE client_name = $1 AND state = 'pending'",
    )
    .bind(client_name)
    .fetch_one(db)
    .await?)
}

pub async fn get_request(db: &PgPool, id: Uuid) -> anyhow::Result<Option<AccessRequestRow>> {
    Ok(
        sqlx::query_as::<_, AccessRequestRow>("SELECT * FROM access_requests WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn list_pending(db: &PgPool) -> anyhow::Result<Vec<AccessRequestRow>> {
    Ok(sqlx::query_as::<_, AccessRequestRow>(
        "SELECT * FROM access_requests WHERE state = 'pending' ORDER BY created_at",
    )
    .fetch_all(db)
    .await?)
}

/// Passthrough payload attached to a grant at approval time (secret entered
/// but not stored).
#[derive(Debug, Clone)]
pub struct PassthroughPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    /// True when wrapped under the process-local ephemeral KEK.
    pub ephemeral: bool,
}

/// Grant fields decided at approval time (constraints possibly narrowed,
/// `not_after` already capped against policy expiry by the caller).
#[derive(Debug, Clone)]
pub struct GrantParams {
    pub client_name: String,
    pub secret_name: String,
    pub mechanism: String,
    pub constraints: serde_json::Value,
    pub not_after: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub passthrough: Option<PassthroughPayload>,
}

/// Approve a pending request: in one transaction, flip `pending -> approved`
/// (rowcount-checked), insert the grant, and write the `request-approved`
/// audit row. Returns the new grant id, or `None` if the request was not
/// pending (already resolved or expired) — nothing is written in that case.
pub async fn resolve_approve(
    db: &PgPool,
    request_id: Uuid,
    resolved_by: &str,
    grant: &GrantParams,
) -> anyhow::Result<Option<Uuid>> {
    let mut tx = db.begin().await?;
    let updated = sqlx::query(
        "UPDATE access_requests \
         SET state = 'approved', resolved_by = $2, resolved_at = now() \
         WHERE id = $1 AND state = 'pending' AND now() < expires_at",
    )
    .bind(request_id)
    .bind(resolved_by)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Ok(None);
    }
    let (pt_ct, pt_nonce, pt_dek, pt_eph) = match &grant.passthrough {
        Some(p) => (
            Some(&p.ciphertext),
            Some(&p.nonce),
            Some(&p.wrapped_dek),
            p.ephemeral,
        ),
        None => (None, None, None, false),
    };
    let grant_id: Uuid = sqlx::query_scalar(
        "INSERT INTO grants \
         (request_id, client_name, secret_name, mechanism, constraints, not_after, max_uses, \
          passthrough_ciphertext, passthrough_nonce, passthrough_wrapped_dek, passthrough_ephemeral) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         RETURNING id",
    )
    .bind(request_id)
    .bind(&grant.client_name)
    .bind(&grant.secret_name)
    .bind(&grant.mechanism)
    .bind(&grant.constraints)
    .bind(grant.not_after)
    .bind(grant.max_uses)
    .bind(pt_ct)
    .bind(pt_nonce)
    .bind(pt_dek)
    .bind(pt_eph)
    .fetch_one(&mut *tx)
    .await?;
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::REQUEST_APPROVED,
            request_id: Some(request_id),
            grant_id: Some(grant_id),
            client_name: Some(grant.client_name.clone()),
            secret_name: Some(grant.secret_name.clone()),
            actor: Some(resolved_by.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Some(grant_id))
}

/// Deny a pending request (`pending -> denied`) plus audit row, atomically.
/// Returns false if the request was not pending.
pub async fn resolve_deny(
    db: &PgPool,
    request_id: Uuid,
    resolved_by: &str,
    reason: &str,
) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "UPDATE access_requests \
         SET state = 'denied', deny_reason = $2, resolved_by = $3, resolved_at = now() \
         WHERE id = $1 AND state = 'pending' AND now() < expires_at \
         RETURNING client_name, secret_name",
    )
    .bind(request_id)
    .bind(reason)
    .bind(resolved_by)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((client_name, secret_name)) = row else {
        return Ok(false);
    };
    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::REQUEST_DENIED,
            request_id: Some(request_id),
            client_name: Some(client_name),
            secret_name: Some(secret_name),
            actor: Some(resolved_by.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Expire pending requests past their deadline. Encrypted context is purged
/// with the transition (the request is terminal; the approval page will never
/// render it). Returns the number of requests expired.
pub async fn expire_stale(db: &PgPool, now: DateTime<Utc>) -> anyhow::Result<u64> {
    let mut tx = db.begin().await?;
    let expired: Vec<(Uuid, String, String)> = sqlx::query_as(
        "UPDATE access_requests \
         SET state = 'expired', resolved_at = $1, \
             context_ciphertext = NULL, context_nonce = NULL, \
             context_wrapped_dek = NULL, context_kek_id = NULL \
         WHERE state = 'pending' AND expires_at < $1 \
         RETURNING id, client_name, secret_name",
    )
    .bind(now)
    .fetch_all(&mut *tx)
    .await?;
    for (id, client_name, secret_name) in &expired {
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::REQUEST_EXPIRED,
                request_id: Some(*id),
                client_name: Some(client_name.clone()),
                secret_name: Some(secret_name.clone()),
                ..Default::default()
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(expired.len() as u64)
}

/// Purge encrypted context from requests that reached a terminal state before
/// `cutoff` (retention decided by the sweeper). Returns rows purged.
pub async fn purge_request_context(db: &PgPool, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
    let res = sqlx::query(
        "UPDATE access_requests \
         SET context_ciphertext = NULL, context_nonce = NULL, \
             context_wrapped_dek = NULL, context_kek_id = NULL \
         WHERE state <> 'pending' AND resolved_at IS NOT NULL AND resolved_at < $1 \
           AND context_ciphertext IS NOT NULL",
    )
    .bind(cutoff)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

pub async fn mark_push_delivered(db: &PgPool, request_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE access_requests SET push_delivered_at = now() WHERE id = $1")
        .bind(request_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Unconditional counter bump. Both push paths use
/// `notify::claim_for_push` instead: it bumps the counter only while the row
/// is still pushable, which is also the permission to send.
pub async fn increment_push_attempts(db: &PgPool, request_id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE access_requests SET push_attempts = push_attempts + 1 WHERE id = $1")
        .bind(request_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Pending, unexpired requests whose approval push has not been delivered and
/// which still have retry budget. The request row is the outbox.
pub async fn list_pending_needing_push(
    db: &PgPool,
    max_attempts: i32,
) -> anyhow::Result<Vec<AccessRequestRow>> {
    Ok(sqlx::query_as::<_, AccessRequestRow>(
        "SELECT * FROM access_requests \
         WHERE state = 'pending' AND push_delivered_at IS NULL \
           AND push_attempts < $1 AND expires_at > now() \
         ORDER BY created_at",
    )
    .bind(max_attempts)
    .fetch_all(db)
    .await?)
}
