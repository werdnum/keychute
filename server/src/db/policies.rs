//! Policy rows (standing grants / auto-approval / deny rules).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolicyRow {
    pub id: Uuid,
    pub client_name: Option<String>,
    pub secret_name: Option<String>,
    pub secret_tag: Option<String>,
    pub mechanism: String,
    pub outcome: String,
    pub priority: i32,
    pub origins: serde_json::Value,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub max_ttl_seconds: Option<i64>,
    pub max_uses: Option<i32>,
    pub not_after: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewPolicy {
    pub client_name: Option<String>,
    pub secret_name: Option<String>,
    pub secret_tag: Option<String>,
    pub mechanism: String,
    pub outcome: String,
    pub priority: i32,
    pub origins: serde_json::Value,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub max_ttl_seconds: Option<i64>,
    pub max_uses: Option<i32>,
    pub not_after: Option<DateTime<Utc>>,
    pub created_by: String,
}

pub async fn list_policies(db: &PgPool) -> anyhow::Result<Vec<PolicyRow>> {
    Ok(
        sqlx::query_as::<_, PolicyRow>("SELECT * FROM policies ORDER BY created_at")
            .fetch_all(db)
            .await?,
    )
}

pub async fn insert_policy(db: &PgPool, p: &NewPolicy) -> anyhow::Result<PolicyRow> {
    Ok(sqlx::query_as::<_, PolicyRow>(
        "INSERT INTO policies \
         (client_name, secret_name, secret_tag, mechanism, outcome, priority, origins, \
          methods, path_prefixes, max_ttl_seconds, max_uses, not_after, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING *",
    )
    .bind(&p.client_name)
    .bind(&p.secret_name)
    .bind(&p.secret_tag)
    .bind(&p.mechanism)
    .bind(&p.outcome)
    .bind(p.priority)
    .bind(&p.origins)
    .bind(&p.methods)
    .bind(&p.path_prefixes)
    .bind(p.max_ttl_seconds)
    .bind(p.max_uses)
    .bind(p.not_after)
    .bind(&p.created_by)
    .fetch_one(db)
    .await?)
}

/// Delete a policy row. Deletion does not retro-revoke issued grants (they
/// already carry a capped `not_after`). Returns false when no row matched.
pub async fn delete_policy(db: &PgPool, id: Uuid) -> anyhow::Result<bool> {
    let res = sqlx::query("DELETE FROM policies WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() == 1)
}
