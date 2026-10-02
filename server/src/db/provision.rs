//! Declarative provisioning of secrets and policy rows from config (GitOps).
//!
//! Same model as client reconciliation ([`super::reconcile_clients`]): the
//! config file is the source of truth for the rows it manages, and startup
//! makes the database match it. Rows are marked `managed_by_config`
//! (migration 0009) so reconciliation knows which ones it owns — it never
//! touches a secret or policy an operator created in the UI, except to adopt a
//! secret whose name the config now claims.
//!
//! Every change is audited with actor [`CONFIG_ACTOR`]; a restart that changes
//! nothing writes nothing.

use super::policies::NewPolicy;
use super::secrets::SecretRow;
use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::crypto::{AadContext, Keyset, SecretBytes};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Audit actor and `created_by` for everything reconciliation writes.
pub const CONFIG_ACTOR: &str = "config";

/// A secret as the config wants it, with its value already read from file.
pub struct DesiredSecret {
    pub name: String,
    pub description: String,
    pub max_tier: i32,
    pub injection_kind: String,
    pub injection_header: Option<String>,
    pub injection_username: Option<String>,
    pub tags: Vec<String>,
    pub value: SecretBytes,
}

/// What reconciling one secret did, for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretChange {
    Created,
    /// Metadata and/or value changed on an existing row.
    Updated {
        metadata: bool,
        rotated: bool,
    },
    Unchanged,
}

/// Reconcile provisioned secrets: create or update every desired secret, then
/// delete the managed rows the config no longer lists.
pub async fn reconcile_secrets(
    db: &PgPool,
    keyset: &Keyset,
    desired: &[DesiredSecret],
) -> anyhow::Result<Vec<(String, SecretChange)>> {
    let mut changes = Vec::new();
    for d in desired {
        let change = reconcile_one_secret(db, keyset, d).await?;
        changes.push((d.name.clone(), change));
    }
    let names: Vec<&str> = desired.iter().map(|d| d.name.as_str()).collect();
    let stale: Vec<(Uuid, i32, String)> = sqlx::query_as(
        "SELECT id, current_version, name FROM secrets \
         WHERE managed_by_config AND name <> ALL($1)",
    )
    .bind(&names)
    .fetch_all(db)
    .await?;
    for (id, version, name) in stale {
        // Same path as an operator's confirmed delete: versions go with the
        // row and dependent grants are revoked, all audited.
        let outcome = super::ui_ext::delete_secret_audited(db, id, version, CONFIG_ACTOR).await?;
        tracing::info!(secret = %name, ?outcome, "removed secret no longer in config");
    }
    Ok(changes)
}

async fn reconcile_one_secret(
    db: &PgPool,
    keyset: &Keyset,
    d: &DesiredSecret,
) -> anyhow::Result<SecretChange> {
    let mut tx = db.begin().await?;
    super::take_kek_shared_lock(&mut tx).await?;
    let existing =
        sqlx::query_as::<_, SecretRow>("SELECT * FROM secrets WHERE name = $1 FOR UPDATE")
            .bind(&d.name)
            .fetch_optional(&mut *tx)
            .await?;

    let Some(row) = existing else {
        let secret_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO secrets \
             (id, name, description, max_tier, injection_kind, injection_header, \
              injection_username, current_version, operator_vetted, managed_by_config) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 1, true, true)",
        )
        .bind(secret_id)
        .bind(&d.name)
        .bind(&d.description)
        .bind(d.max_tier)
        .bind(&d.injection_kind)
        .bind(&d.injection_header)
        .bind(&d.injection_username)
        .execute(&mut *tx)
        .await?;
        let version_id = insert_version(&mut tx, keyset, secret_id, 1, &d.value).await?;
        replace_tags(&mut tx, secret_id, &d.tags).await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::SECRET_CREATED,
                secret_name: Some(d.name.clone()),
                secret_version_id: Some(version_id),
                actor: Some(CONFIG_ACTOR.to_owned()),
                ..Default::default()
            },
        )
        .await?;
        tx.commit().await?;
        return Ok(SecretChange::Created);
    };

    let current_tags: Vec<String> =
        sqlx::query_scalar("SELECT tag FROM secret_tags WHERE secret_id = $1 ORDER BY tag")
            .bind(row.id)
            .fetch_all(&mut *tx)
            .await?;
    let mut wanted_tags = d.tags.clone();
    wanted_tags.sort();
    wanted_tags.dedup();
    let metadata = row.description != d.description
        || row.max_tier != d.max_tier
        || row.injection_kind != d.injection_kind
        || row.injection_header != d.injection_header
        || row.injection_username != d.injection_username
        || !row.enabled
        || !row.operator_vetted
        || !row.managed_by_config
        || current_tags != wanted_tags;
    if metadata {
        sqlx::query(
            "UPDATE secrets SET description = $2, max_tier = $3, injection_kind = $4, \
             injection_header = $5, injection_username = $6, enabled = true, \
             operator_vetted = true, managed_by_config = true, updated_at = now() \
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(&d.description)
        .bind(d.max_tier)
        .bind(&d.injection_kind)
        .bind(&d.injection_header)
        .bind(&d.injection_username)
        .execute(&mut *tx)
        .await?;
        replace_tags(&mut tx, row.id, &wanted_tags).await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::SECRET_UPDATED,
                secret_name: Some(d.name.clone()),
                actor: Some(CONFIG_ACTOR.to_owned()),
                detail: Some(serde_json::json!({
                    "max_tier": d.max_tier,
                    "injection_kind": d.injection_kind,
                    "adopted": !row.managed_by_config,
                })),
                ..Default::default()
            },
        )
        .await?;
    }

    // Rotate only when the bytes differ, so restarts don't mint versions.
    let current = sqlx::query_as::<_, super::secrets::SecretVersionRow>(
        "SELECT * FROM secret_versions WHERE secret_id = $1 AND version = $2",
    )
    .bind(row.id)
    .bind(row.current_version)
    .fetch_optional(&mut *tx)
    .await?;
    let same = match &current {
        Some(v) => {
            let plaintext = keyset.open(
                &v.ciphertext,
                &v.nonce,
                &v.wrapped_dek,
                &v.kek_id,
                AadContext::SecretVersion {
                    secret_id: v.secret_id,
                    version: v.version,
                },
            )?;
            bool::from(plaintext.expose_secret().ct_eq(d.value.expose_secret()))
        }
        None => false,
    };
    let rotated = !same;
    if rotated {
        let version: i32 = sqlx::query_scalar(
            "UPDATE secrets SET current_version = current_version + 1, updated_at = now() \
             WHERE id = $1 RETURNING current_version",
        )
        .bind(row.id)
        .fetch_one(&mut *tx)
        .await?;
        let version_id = insert_version(&mut tx, keyset, row.id, version, &d.value).await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::SECRET_ROTATED,
                secret_name: Some(d.name.clone()),
                secret_version_id: Some(version_id),
                actor: Some(CONFIG_ACTOR.to_owned()),
                ..Default::default()
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(if metadata || rotated {
        SecretChange::Updated { metadata, rotated }
    } else {
        SecretChange::Unchanged
    })
}

/// Seal and insert one version row; the caller holds the KEK shared lock.
async fn insert_version(
    tx: &mut sqlx::PgConnection,
    keyset: &Keyset,
    secret_id: Uuid,
    version: i32,
    value: &SecretBytes,
) -> anyhow::Result<Uuid> {
    let sealed = keyset
        .seal(value, AadContext::SecretVersion { secret_id, version })
        .map_err(|e| anyhow::anyhow!("sealing provisioned secret: {e}"))?;
    Ok(sqlx::query_scalar(
        "INSERT INTO secret_versions \
         (secret_id, version, ciphertext, nonce, wrapped_dek, kek_id) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(secret_id)
    .bind(version)
    .bind(&sealed.ciphertext)
    .bind(&sealed.nonce)
    .bind(&sealed.wrapped_dek)
    .bind(&sealed.kek_id)
    .fetch_one(tx)
    .await?)
}

async fn replace_tags(
    tx: &mut sqlx::PgConnection,
    secret_id: Uuid,
    tags: &[String],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM secret_tags WHERE secret_id = $1")
        .bind(secret_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO secret_tags (secret_id, tag) SELECT $1, unnest($2::text[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(secret_id)
    .bind(tags)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Everything that makes two policy rows the same rule. Managed rows whose key
/// is still in config are left alone (stable ids, no audit churn per restart).
fn policy_key(p: &NewPolicy) -> serde_json::Value {
    serde_json::json!([
        p.client_name,
        p.secret_name,
        p.secret_tag,
        p.mechanism,
        p.outcome,
        p.priority,
        p.origins,
        p.methods,
        p.path_prefixes,
        p.max_ttl_seconds,
        p.max_uses,
        // Postgres keeps microseconds; config may carry more.
        p.not_after.map(|t| t.timestamp_micros()),
    ])
}

/// Counts of what [`reconcile_policies`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyChanges {
    pub created: usize,
    pub deleted: usize,
}

/// Reconcile provisioned policy rows in one transaction: insert the config
/// rules that have no managed row yet, delete managed rows the config no
/// longer has. A changed rule is a delete plus an insert.
pub async fn reconcile_policies(
    db: &PgPool,
    desired: &[NewPolicy],
) -> anyhow::Result<PolicyChanges> {
    let mut tx = db.begin().await?;
    let existing = sqlx::query_as::<_, super::policies::PolicyRow>(
        "SELECT * FROM policies WHERE managed_by_config FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut wanted: Vec<(serde_json::Value, &NewPolicy)> =
        desired.iter().map(|p| (policy_key(p), p)).collect();
    let mut changes = PolicyChanges::default();
    for row in existing {
        let key = policy_key(&NewPolicy {
            client_name: row.client_name.clone(),
            secret_name: row.secret_name.clone(),
            secret_tag: row.secret_tag.clone(),
            mechanism: row.mechanism.clone(),
            outcome: row.outcome.clone(),
            priority: row.priority,
            origins: row.origins.clone(),
            methods: row.methods.clone(),
            path_prefixes: row.path_prefixes.clone(),
            max_ttl_seconds: row.max_ttl_seconds,
            max_uses: row.max_uses,
            not_after: row.not_after,
            created_by: row.created_by.clone(),
        });
        if let Some(i) = wanted.iter().position(|(k, _)| *k == key) {
            wanted.swap_remove(i);
            continue;
        }
        sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::POLICY_DELETED,
                client_name: row.client_name,
                secret_name: row.secret_name,
                actor: Some(CONFIG_ACTOR.to_owned()),
                detail: Some(serde_json::json!({ "policy_id": row.id })),
                ..Default::default()
            },
        )
        .await?;
        changes.deleted += 1;
    }
    for (_, p) in wanted {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO policies \
             (client_name, secret_name, secret_tag, mechanism, outcome, priority, origins, \
              methods, path_prefixes, max_ttl_seconds, max_uses, not_after, created_by, \
              managed_by_config) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, true) \
             RETURNING id",
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
        .bind(CONFIG_ACTOR)
        .fetch_one(&mut *tx)
        .await?;
        insert_audit(
            &mut *tx,
            &AuditEvent {
                kind: kinds::POLICY_CREATED,
                client_name: p.client_name.clone(),
                secret_name: p.secret_name.clone(),
                actor: Some(CONFIG_ACTOR.to_owned()),
                detail: Some(serde_json::json!({
                    "policy_id": id,
                    "mechanism": p.mechanism,
                    "outcome": p.outcome,
                })),
                ..Default::default()
            },
        )
        .await?;
        changes.created += 1;
    }
    tx.commit().await?;
    Ok(changes)
}

/// Read every provisioned secret's files and resolve its template. Fails if
/// any file is unreadable or empty: a deployment whose Secret is missing a
/// key should not start with that credential silently absent.
pub fn desired_secrets(
    configs: &[crate::config::SecretConfig],
) -> anyhow::Result<Vec<DesiredSecret>> {
    use anyhow::Context;
    configs
        .iter()
        .map(|c| {
            let (injection_kind, injection_header, injection_username) = c
                .injection
                .resolve()
                .with_context(|| format!("secret {}: injection", c.name))?;
            let raw = zeroize::Zeroizing::new(std::fs::read(&c.value_file).with_context(|| {
                format!("secret {}: reading {}", c.name, c.value_file.display())
            })?);
            let value = crate::config::trim_one_newline(&raw);
            if value.is_empty() {
                anyhow::bail!("secret {}: {} is empty", c.name, c.value_file.display());
            }
            Ok(DesiredSecret {
                name: c.name.clone(),
                description: c.description.clone(),
                max_tier: c.max_tier.as_int(),
                injection_kind,
                injection_header,
                injection_username,
                tags: c.tags.clone(),
                value: SecretBytes::new(value.into()),
            })
        })
        .collect()
}
