//! Store-layer additions owned by the client-API task. Keep API-specific
//! queries here rather than editing the Phase-A modules.

use crate::audit::{insert_audit, kinds, AuditEvent};

use super::clients::ClientRow;
use super::grants::GrantRow;
use super::requests::{AccessRequestRow, GrantParams, NewAccessRequest};
use sqlx::PgPool;
use uuid::Uuid;

/// The policy outcome decided *before* the insert, applied inside the same
/// transaction so a created request is never observably pending when policy
/// already decided it (a partial failure would otherwise leave a
/// policy-denied request sitting in the operator's approval queue, and an
/// idempotent retry would return that pending state without re-evaluating).
pub enum InitialResolution<'a> {
    /// Standing policy requires a human: the row is created `pending`.
    Pending,
    /// Policy denied: the row is created `denied` with its audit row.
    Denied {
        reason: &'a str,
        resolved_by: &'a str,
    },
    /// Policy auto-approved: the row is created `approved` and the grant is
    /// minted in the same transaction.
    Approved {
        resolved_by: &'a str,
        grant: &'a GrantParams,
    },
}

/// Outcome of [`insert_access_request_with_id`].
#[derive(Debug, Clone)]
pub enum InsertOutcome {
    /// New row committed (with its `request-created` audit row, and — when
    /// policy already decided — its resolution and grant, in the same
    /// transaction).
    Created {
        row: AccessRequestRow,
        /// Set when the request was created already-approved.
        grant_id: Option<Uuid>,
    },
    /// An existing row for (idem_client, idem_key) was returned — an
    /// idempotent retry. The caller decides 200-vs-409 by comparing
    /// `idem_mac` with the MAC of the incoming payload. Never subject to the
    /// pending cap.
    Existing(AccessRequestRow),
    /// The insert was rolled back: it would have pushed the client's pending
    /// count over `pending_cap`. Nothing was written (no row, no audit).
    PendingCapExceeded,
}

/// Idempotent insert with an app-generated request id. The id must be known
/// before insert so the client context can be sealed with a
/// `RequestContext { request_id }` AAD. Same `ON CONFLICT` semantics as
/// [`super::requests::insert_access_request`].
///
/// One transaction: KEK shared advisory lock (when a wrapped DEK is stored,
/// addendum #19), the context seal, the insert, the pending-cap check
/// (`pending_cap`, applied only to newly created rows so idempotent retries
/// always succeed), the `request-created` audit row, and — when policy already
/// decided the outcome (`resolution`) — the deny/approve transition, the
/// grant, and the corresponding resolution audit row. Creation and resolution
/// therefore commit together: an `Existing` row always carries the decided
/// state.
///
/// `seal_context` (`Some` when the client sent a context) runs INSIDE this
/// transaction, after the lock: see [`super::SealFn`].
pub async fn insert_access_request_with_id(
    db: &PgPool,
    id: Uuid,
    req: &NewAccessRequest,
    pending_cap: Option<i64>,
    resolution: &InitialResolution<'_>,
    seal_context: Option<super::SealFn<'_>>,
) -> anyhow::Result<InsertOutcome> {
    let mut tx = db.begin().await?;
    // Same pattern as `ui_ext::approve_request`: the lock must cover EVERY
    // wrapped-DEK insert in this transaction — the sealed request context AND
    // an auto-approve grant's passthrough payload (currently always None from
    // the API path, but the store layer must not depend on that).
    let inserts_wrapped_dek = seal_context.is_some()
        || matches!(resolution,
            InitialResolution::Approved { grant, .. } if grant.passthrough.is_some());
    if inserts_wrapped_dek {
        super::take_kek_shared_lock(&mut tx).await?;
    }
    // Sealed under the lock, never before it.
    let context = match seal_context {
        Some(seal) => Some(seal().map_err(|e| anyhow::anyhow!("sealing request context: {e}"))?),
        None => None,
    };
    if pending_cap.is_some() {
        // Serialize per-client creation so concurrent inserts cannot each see
        // only themselves under READ COMMITTED and collectively exceed the cap.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keychute-pending-' || $1))")
            .bind(&req.client_name)
            .execute(&mut *tx)
            .await?;
    }
    let inserted = sqlx::query_as::<_, AccessRequestRow>(
        "INSERT INTO access_requests \
         (id, client_name, secret_name, mechanism, constraints, \
          context_ciphertext, context_nonce, context_wrapped_dek, context_kek_id, \
          expires_at, policy_not_after, idem_client, idem_key, idem_mac) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (idem_client, idem_key) DO NOTHING \
         RETURNING *",
    )
    .bind(id)
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
    if let Some(mut row) = inserted {
        if let Some(cap) = pending_cap {
            // Expired-but-unswept rows must not count toward the cap: during a
            // stalled sweep a client whose pending requests have all expired
            // would otherwise stay 429'd. Expiry on the DB clock, matching the
            // approve/deny/expire predicates.
            let pending: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM access_requests \
                 WHERE client_name = $1 AND state = 'pending' AND now() < expires_at",
            )
            .bind(&req.client_name)
            .fetch_one(&mut *tx)
            .await?;
            // The count includes the row just inserted.
            if pending > cap {
                tx.rollback().await?;
                return Ok(InsertOutcome::PendingCapExceeded);
            }
        }
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::REQUEST_CREATED,
                request_id: Some(row.id),
                client_name: Some(req.client_name.clone()),
                secret_name: Some(req.secret_name.clone()),
                detail: Some(serde_json::json!({ "mechanism": req.mechanism })),
                ..Default::default()
            },
        )
        .await?;
        // Policy already decided: apply the resolution in this same
        // transaction so the row is never observably pending.
        let mut grant_id = None;
        match resolution {
            InitialResolution::Pending => {}
            InitialResolution::Denied {
                reason,
                resolved_by,
            } => {
                row = sqlx::query_as::<_, AccessRequestRow>(
                    "UPDATE access_requests \
                     SET state = 'denied', deny_reason = $2, resolved_by = $3, \
                         resolved_at = now() \
                     WHERE id = $1 RETURNING *",
                )
                .bind(row.id)
                .bind(reason)
                .bind(resolved_by)
                .fetch_one(&mut *tx)
                .await?;
                insert_audit(
                    &mut *tx,
                    &AuditEvent {
                        kind: kinds::REQUEST_DENIED,
                        request_id: Some(row.id),
                        client_name: Some(req.client_name.clone()),
                        secret_name: Some(req.secret_name.clone()),
                        actor: Some((*resolved_by).to_owned()),
                        ..Default::default()
                    },
                )
                .await?;
            }
            InitialResolution::Approved { resolved_by, grant } => {
                row = sqlx::query_as::<_, AccessRequestRow>(
                    "UPDATE access_requests \
                     SET state = 'approved', resolved_by = $2, resolved_at = now() \
                     WHERE id = $1 RETURNING *",
                )
                .bind(row.id)
                .bind(resolved_by)
                .fetch_one(&mut *tx)
                .await?;
                let (pt_ct, pt_nonce, pt_dek, pt_eph) = match &grant.passthrough {
                    Some(p) => (
                        Some(&p.ciphertext),
                        Some(&p.nonce),
                        Some(&p.wrapped_dek),
                        p.ephemeral,
                    ),
                    None => (None, None, None, false),
                };
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO grants \
                     (request_id, client_name, secret_name, mechanism, constraints, \
                      not_after, max_uses, passthrough_ciphertext, passthrough_nonce, \
                      passthrough_wrapped_dek, passthrough_ephemeral) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                     RETURNING id",
                )
                .bind(row.id)
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
                        request_id: Some(row.id),
                        grant_id: Some(id),
                        client_name: Some(grant.client_name.clone()),
                        secret_name: Some(grant.secret_name.clone()),
                        actor: Some((*resolved_by).to_owned()),
                        ..Default::default()
                    },
                )
                .await?;
                grant_id = Some(id);
            }
        }
        tx.commit().await?;
        return Ok(InsertOutcome::Created { row, grant_id });
    }
    tx.rollback().await?;
    let row = sqlx::query_as::<_, AccessRequestRow>(
        "SELECT * FROM access_requests WHERE idem_client = $1 AND idem_key = $2",
    )
    .bind(&req.idem_client)
    .bind(&req.idem_key)
    .fetch_one(db)
    .await?;
    Ok(InsertOutcome::Existing(row))
}

/// The grant minted for a request, if any (unique on request_id).
pub async fn get_grant_by_request(
    db: &PgPool,
    request_id: Uuid,
) -> anyhow::Result<Option<GrantRow>> {
    Ok(
        sqlx::query_as::<_, GrantRow>("SELECT * FROM grants WHERE request_id = $1")
            .bind(request_id)
            .fetch_optional(db)
            .await?,
    )
}

/// Look up a client by its API-token hash. Equality in SQL is acceptable
/// here: the SHA-256 hash of the presented token is not secret material and
/// the index lookup's timing does not depend on the stored token (the caller
/// already knows what they presented); the caller still re-verifies the full
/// hash with a constant-time compare (`crypto::ct_eq`).
pub async fn get_client_by_token_hash(
    db: &PgPool,
    token_sha256_hex: &str,
) -> anyhow::Result<Option<ClientRow>> {
    Ok(
        sqlx::query_as::<_, ClientRow>("SELECT * FROM clients WHERE api_token_sha256 = $1")
            .bind(token_sha256_hex)
            .fetch_optional(db)
            .await?,
    )
}

/// All client rows bound to a service-account subject (the caller filters by
/// audience and enabled per addendum #3).
pub async fn get_clients_by_sa_subject(
    db: &PgPool,
    subject: &str,
) -> anyhow::Result<Vec<ClientRow>> {
    Ok(
        sqlx::query_as::<_, ClientRow>("SELECT * FROM clients WHERE sa_subject = $1")
            .bind(subject)
            .fetch_all(db)
            .await?,
    )
}

/// Username for `basic` credential injection (column added in migration
/// 0003; not part of the Phase-A `SecretRow`).
pub async fn get_injection_username(
    db: &PgPool,
    secret_id: Uuid,
) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT injection_username FROM secrets WHERE id = $1")
            .bind(secret_id)
            .fetch_optional(db)
            .await?
            .flatten(),
    )
}
