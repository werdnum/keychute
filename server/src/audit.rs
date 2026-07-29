//! Audit log helpers.
//!
//! Every row is append-only. `detail` must NEVER contain secret material or
//! freeform client context — only server vocabulary (flags, counts, reason
//! codes). See docs/IMPLEMENTATION.md §DB schema.

use uuid::Uuid;

/// Well-known audit event kinds.
pub mod kinds {
    pub const REQUEST_CREATED: &str = "request-created";
    pub const REQUEST_APPROVED: &str = "request-approved";
    pub const REQUEST_DENIED: &str = "request-denied";
    pub const REQUEST_EXPIRED: &str = "request-expired";
    pub const GRANT_REVOKED: &str = "grant-revoked";
    /// Write-ahead row: commits with use-accounting BEFORE plaintext leaves.
    pub const RELEASE_ATTEMPT: &str = "release-attempt";
    pub const RELEASE_COMPLETED: &str = "release-completed";
    /// Write-ahead row for the brokered proxy leg.
    pub const PROXY_ATTEMPT: &str = "proxy-attempt";
    pub const PROXY_COMPLETED: &str = "proxy-completed";
    pub const SECRET_CREATED: &str = "secret-created";
    pub const SECRET_ROTATED: &str = "secret-rotated";
    /// An operator reviewed a client-deposited secret (migration 0007).
    pub const SECRET_VETTED: &str = "secret-vetted";
    pub const POLICY_CREATED: &str = "policy-created";
    pub const POLICY_DELETED: &str = "policy-deleted";
}

/// One audit_log row. `at` is assigned by the database (`now()`).
#[derive(Debug, Clone, Default)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub request_id: Option<Uuid>,
    pub grant_id: Option<Uuid>,
    pub client_name: Option<String>,
    pub secret_name: Option<String>,
    /// Immutable id of the payload actually decrypted: a secret_version id,
    /// or the grant id itself for passthrough payloads.
    pub secret_version_id: Option<Uuid>,
    pub actor: Option<String>,
    pub method: Option<String>,
    pub origin: Option<String>,
    pub path: Option<String>,
    pub status: Option<i32>,
    /// Structured server vocabulary only — never secrets or client context.
    pub detail: Option<serde_json::Value>,
}

/// Insert one audit row. Generic over the executor so callers can join an
/// open transaction (`&mut *tx`) or use the pool directly.
pub async fn insert_audit<'e, E>(executor: E, ev: &AuditEvent) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO audit_log \
         (kind, request_id, grant_id, client_name, secret_name, secret_version_id, \
          actor, method, origin, path, status, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(ev.kind)
    .bind(ev.request_id)
    .bind(ev.grant_id)
    .bind(&ev.client_name)
    .bind(&ev.secret_name)
    .bind(ev.secret_version_id)
    .bind(&ev.actor)
    .bind(&ev.method)
    .bind(&ev.origin)
    .bind(&ev.path)
    .bind(ev.status)
    .bind(&ev.detail)
    .execute(executor)
    .await?;
    Ok(())
}
