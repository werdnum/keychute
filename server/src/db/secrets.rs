//! Stored secrets and their append-only version rows.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecretRow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub max_tier: i32,
    pub injection_kind: String,
    pub injection_header: Option<String>,
    pub current_version: i32,
    pub enabled: bool,
    /// Has an operator ever seen this value? False for a client deposit until
    /// one reviews it (migration 0007): the policy engine keeps such a secret
    /// under the same "never auto-approve" clamp as one that does not exist.
    pub operator_vetted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecretVersionRow {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub version: i32,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub kek_id: String,
    pub created_at: DateTime<Utc>,
    pub created_by_request: Option<Uuid>,
}

pub async fn create_secret(
    db: &PgPool,
    name: &str,
    description: &str,
    max_tier: i32,
    injection_kind: &str,
    injection_header: Option<&str>,
) -> anyhow::Result<SecretRow> {
    Ok(sqlx::query_as::<_, SecretRow>(
        "INSERT INTO secrets (name, description, max_tier, injection_kind, injection_header) \
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(name)
    .bind(description)
    .bind(max_tier)
    .bind(injection_kind)
    .bind(injection_header)
    .fetch_one(db)
    .await?)
}

/// Append a new secret version: atomically bumps `secrets.current_version`
/// and inserts the version row with that number in one transaction. `seal`
/// receives the new version number (its AAD binds it) and runs inside the
/// transaction, after the KEK shared lock — same discipline as
/// [`crate::db::ui_ext::rotate_secret_version`].
pub async fn insert_secret_version(
    db: &PgPool,
    secret_id: Uuid,
    seal: impl FnOnce(i32) -> Result<crate::crypto::Sealed, crate::crypto::CryptoError>,
    created_by_request: Option<Uuid>,
) -> anyhow::Result<SecretVersionRow> {
    let mut tx = db.begin().await?;
    // Addendum #19: every wrapped-DEK writer holds the shared KEK lock, and
    // seals only once it does.
    super::take_kek_shared_lock(&mut tx).await?;
    let version: i32 = sqlx::query_scalar(
        "UPDATE secrets SET current_version = current_version + 1, updated_at = now() \
         WHERE id = $1 RETURNING current_version",
    )
    .bind(secret_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
    let sealed = seal(version).map_err(|e| anyhow::anyhow!("sealing secret version: {e}"))?;
    let row = sqlx::query_as::<_, SecretVersionRow>(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id, created_by_request) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
    )
    .bind(secret_id)
    .bind(version)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.kek_id)
    .bind(created_by_request)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Outcome of a client-initiated deposit. The rate decision lives here rather
/// than in the handler because it is only meaningful when taken atomically
/// with the write (see [`create_secret_from_client`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositOutcome {
    Created(Uuid),
    /// A secret of that name already exists — 409, never a rotation.
    NameTaken,
    /// The client's hourly deposit cap is already spent — 429.
    RateLimited,
}

/// Client-initiated deposit (`POST /v1/secrets`): create a secret with its
/// version 1, but ONLY if the name is free and the client is under its hourly
/// deposit cap.
///
/// Create-only by construction: `ON CONFLICT (name) DO NOTHING` decides inside
/// the transaction, so two concurrent deposits (or a deposit racing an
/// operator's `POST /ui/secrets`) cannot both win, and a client can never
/// replace credential bytes an operator already reviewed. Rotation stays
/// operator-only.
///
/// The rate cap is enforced in the SAME transaction, behind a per-client
/// advisory lock taken first: without it, N concurrent deposits could each read
/// the pre-deposit count, all pass, and all insert — the cap would bound
/// nothing but a serial client. The lock serializes one client's deposits
/// against each other only; different clients never contend.
///
/// Same crypto discipline as [`crate::db::ui_ext::create_secret_with_version`]:
/// the KEK shared lock is taken before sealing and the payload is sealed inside
/// the writing transaction (addendum #19). The `secret-created` audit row joins
/// the same transaction and records the depositing client — which is also what
/// the cap counts, so the count can never drift from what actually happened.
pub async fn create_secret_from_client(
    db: &PgPool,
    store: crate::db::ui_ext::StoreSecretParams<'_>,
    client_name: &str,
    rate: DepositRate,
) -> anyhow::Result<DepositOutcome> {
    let mut tx = db.begin().await?;
    // Per-client serialization for the count-then-insert below. Taken before
    // the KEK lock, and in that fixed order everywhere, so the two can never
    // deadlock against each other.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('keychute-deposit'), hashtext($1))")
        .bind(client_name)
        .execute(&mut *tx)
        .await?;
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log \
         WHERE kind = $1 AND client_name = $2 AND at > now() - make_interval(hours => $3)",
    )
    .bind(crate::audit::kinds::SECRET_CREATED)
    .bind(client_name)
    .bind(rate.window_hours)
    .fetch_one(&mut *tx)
    .await?;
    if recent >= rate.max_per_window {
        tx.rollback().await?;
        return Ok(DepositOutcome::RateLimited);
    }
    super::take_kek_shared_lock(&mut tx).await?;
    let inserted = sqlx::query(
        // `operator_vetted = false`: nobody has looked at these bytes. Until
        // someone does, the policy engine treats this row like an absent one
        // for auto-approve/notify-only purposes (migration 0007).
        "INSERT INTO secrets \
         (id, name, description, max_tier, injection_kind, injection_header, \
          injection_username, current_version, operator_vetted) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, false) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(store.secret_id)
    .bind(&store.name)
    .bind(&store.description)
    .bind(store.max_tier)
    .bind(&store.injection_kind)
    .bind(&store.injection_header)
    .bind(&store.injection_username)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        tx.rollback().await?;
        return Ok(DepositOutcome::NameTaken);
    }
    let sealed = (store.seal)().map_err(|e| anyhow::anyhow!("sealing secret: {e}"))?;
    sqlx::query(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id) \
         VALUES ($1, 1, $2, $3, $4, $5)",
    )
    .bind(store.secret_id)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.kek_id)
    .execute(&mut *tx)
    .await?;
    crate::audit::insert_audit(
        &mut *tx,
        &crate::audit::AuditEvent {
            kind: crate::audit::kinds::SECRET_CREATED,
            client_name: Some(client_name.to_owned()),
            secret_name: Some(store.name.clone()),
            actor: Some(format!("client:{client_name}")),
            // Server vocabulary only — how the row got here, never its content.
            detail: Some(serde_json::json!({"source": "client-api"})),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(DepositOutcome::Created(store.secret_id))
}

/// The deposit rate cap: at most `max_per_window` deposits per client per
/// rolling `window_hours`.
#[derive(Debug, Clone, Copy)]
pub struct DepositRate {
    pub max_per_window: i64,
    pub window_hours: i32,
}

pub async fn get_secret_by_name(db: &PgPool, name: &str) -> anyhow::Result<Option<SecretRow>> {
    Ok(
        sqlx::query_as::<_, SecretRow>("SELECT * FROM secrets WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn get_secret_version(
    db: &PgPool,
    secret_id: Uuid,
    version: i32,
) -> anyhow::Result<Option<SecretVersionRow>> {
    Ok(sqlx::query_as::<_, SecretVersionRow>(
        "SELECT * FROM secret_versions WHERE secret_id = $1 AND version = $2",
    )
    .bind(secret_id)
    .bind(version)
    .fetch_optional(db)
    .await?)
}

/// Fetch by immutable version id — the pinned-replay path.
pub async fn get_secret_version_by_id(
    db: &PgPool,
    id: Uuid,
) -> anyhow::Result<Option<SecretVersionRow>> {
    Ok(
        sqlx::query_as::<_, SecretVersionRow>("SELECT * FROM secret_versions WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn list_secrets(db: &PgPool) -> anyhow::Result<Vec<SecretRow>> {
    Ok(
        sqlx::query_as::<_, SecretRow>("SELECT * FROM secrets ORDER BY name")
            .fetch_all(db)
            .await?,
    )
}

/// Stored secrets — the count only, for the overview page.
pub async fn count_secrets(db: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM secrets")
        .fetch_one(db)
        .await?)
}

/// Record that an operator has reviewed a client-deposited secret, lifting the
/// policy engine's "never auto-approve an unvetted secret" clamp. Idempotent;
/// returns false when the row is already vetted (or absent) so the caller does
/// not write a second audit row for a no-op.
pub async fn mark_secret_vetted(db: &PgPool, secret_id: Uuid, actor: &str) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    let updated = sqlx::query(
        "UPDATE secrets SET operator_vetted = true, updated_at = now() \
         WHERE id = $1 AND NOT operator_vetted",
    )
    .bind(secret_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    let name: String = sqlx::query_scalar("SELECT name FROM secrets WHERE id = $1")
        .bind(secret_id)
        .fetch_one(&mut *tx)
        .await?;
    crate::audit::insert_audit(
        &mut *tx,
        &crate::audit::AuditEvent {
            kind: crate::audit::kinds::SECRET_VETTED,
            secret_name: Some(name),
            actor: Some(actor.to_owned()),
            ..Default::default()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Replace the tag set for a secret.
pub async fn set_secret_tags(db: &PgPool, secret_id: Uuid, tags: &[String]) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM secret_tags WHERE secret_id = $1")
        .bind(secret_id)
        .execute(&mut *tx)
        .await?;
    for tag in tags {
        sqlx::query(
            "INSERT INTO secret_tags (secret_id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(secret_id)
        .bind(tag)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn get_tags_for_secret(db: &PgPool, secret_id: Uuid) -> anyhow::Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT tag FROM secret_tags WHERE secret_id = $1 ORDER BY tag")
            .bind(secret_id)
            .fetch_all(db)
            .await?,
    )
}
