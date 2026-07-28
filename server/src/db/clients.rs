//! Client rows: declaratively reconciled from config at startup.

use crate::config::ClientConfig;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClientRow {
    pub id: Uuid,
    pub name: String,
    pub max_tier: i32,
    pub mechanisms: Vec<String>,
    pub auth_kind: String,
    pub api_token_sha256: Option<String>,
    pub sa_audience: Option<String>,
    pub sa_subject: Option<String>,
    pub enabled: bool,
}

/// Reconcile the `clients` table from declarative config at startup:
/// upsert by name (re-enabling), disable rows not present in config.
pub async fn reconcile_clients(db: &PgPool, clients: &[ClientConfig]) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    for c in clients {
        let auth_kind = if c.auth.api_token_sha256.is_some() {
            "api-token"
        } else {
            "service-account"
        };
        let mechanisms: Vec<String> = c.mechanisms.iter().map(|m| m.as_str().to_owned()).collect();
        let (sa_audience, sa_subject) = match &c.auth.service_account {
            Some(sa) => (Some(sa.audience.as_str()), Some(sa.subject.as_str())),
            None => (None, None),
        };
        sqlx::query(
            "INSERT INTO clients \
             (name, max_tier, mechanisms, auth_kind, api_token_sha256, sa_audience, sa_subject, enabled) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, true) \
             ON CONFLICT (name) DO UPDATE SET \
               max_tier = EXCLUDED.max_tier, \
               mechanisms = EXCLUDED.mechanisms, \
               auth_kind = EXCLUDED.auth_kind, \
               api_token_sha256 = EXCLUDED.api_token_sha256, \
               sa_audience = EXCLUDED.sa_audience, \
               sa_subject = EXCLUDED.sa_subject, \
               enabled = true",
        )
        .bind(&c.name)
        .bind(c.max_tier.as_int())
        .bind(&mechanisms)
        .bind(auth_kind)
        .bind(&c.auth.api_token_sha256)
        .bind(sa_audience)
        .bind(sa_subject)
        .execute(&mut *tx)
        .await?;
    }
    let names: Vec<String> = clients.iter().map(|c| c.name.clone()).collect();
    sqlx::query("UPDATE clients SET enabled = false WHERE name <> ALL($1)")
        .bind(&names)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn get_client_by_name(db: &PgPool, name: &str) -> anyhow::Result<Option<ClientRow>> {
    Ok(
        sqlx::query_as::<_, ClientRow>("SELECT * FROM clients WHERE name = $1")
            .bind(name)
            .fetch_optional(db)
            .await?,
    )
}

pub async fn list_clients(db: &PgPool) -> anyhow::Result<Vec<ClientRow>> {
    Ok(
        sqlx::query_as::<_, ClientRow>("SELECT * FROM clients ORDER BY name")
            .fetch_all(db)
            .await?,
    )
}
