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
/// and inserts the version row with that number in one transaction.
pub async fn insert_secret_version(
    db: &PgPool,
    secret_id: Uuid,
    ciphertext: &[u8],
    nonce: &[u8],
    wrapped_dek: &[u8],
    kek_id: &str,
    created_by_request: Option<Uuid>,
) -> anyhow::Result<SecretVersionRow> {
    let mut tx = db.begin().await?;
    // Addendum #19: every wrapped-DEK writer holds the shared KEK lock.
    super::take_kek_shared_lock(&mut tx).await?;
    let version: i32 = sqlx::query_scalar(
        "UPDATE secrets SET current_version = current_version + 1, updated_at = now() \
         WHERE id = $1 RETURNING current_version",
    )
    .bind(secret_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
    let row = sqlx::query_as::<_, SecretVersionRow>(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id, created_by_request) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
    )
    .bind(secret_id)
    .bind(version)
    .bind(ciphertext)
    .bind(nonce)
    .bind(wrapped_dek)
    .bind(kek_id)
    .bind(created_by_request)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
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
