//! Store-layer additions owned by the client-API task. Keep API-specific
//! queries here rather than editing the Phase-A modules.

use super::clients::ClientRow;
use super::grants::GrantRow;
use super::requests::{AccessRequestRow, InsertedRequest, NewAccessRequest};
use sqlx::PgPool;
use uuid::Uuid;

/// Idempotent insert with an app-generated request id. The id must be known
/// before insert so the client context can be sealed with a
/// `RequestContext { request_id }` AAD. Same `ON CONFLICT` semantics as
/// [`super::requests::insert_access_request`].
pub async fn insert_access_request_with_id(
    db: &PgPool,
    id: Uuid,
    req: &NewAccessRequest,
) -> anyhow::Result<InsertedRequest> {
    let inserted = sqlx::query_as::<_, AccessRequestRow>(
        "INSERT INTO access_requests \
         (id, client_name, secret_name, mechanism, constraints, \
          context_ciphertext, context_nonce, context_wrapped_dek, context_kek_id, \
          expires_at, idem_client, idem_key, idem_mac) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (idem_client, idem_key) DO NOTHING \
         RETURNING *",
    )
    .bind(id)
    .bind(&req.client_name)
    .bind(&req.secret_name)
    .bind(&req.mechanism)
    .bind(&req.constraints)
    .bind(&req.context_ciphertext)
    .bind(&req.context_nonce)
    .bind(&req.context_wrapped_dek)
    .bind(&req.context_kek_id)
    .bind(req.expires_at)
    .bind(&req.idem_client)
    .bind(&req.idem_key)
    .bind(&req.idem_mac)
    .fetch_optional(db)
    .await?;
    if let Some(row) = inserted {
        return Ok(InsertedRequest { row, created: true });
    }
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
