//! UI-owned SQL for policy mutations.
//!
//! A policy row is an authorization rule: creating or deleting one must land
//! together with its audit row, or a crash between the two statements leaves an
//! active (or silently removed) rule with no audit trail — and retrying the UI
//! action would create a second policy. The store-layer helpers in
//! `db::policies` are single-statement, so the transactional variants live here
//! (same conventions as `db::policies` / `db::ui_ext`: runtime queries with
//! `.bind()`, audit rows joining the same transaction).

use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::db::policies::NewPolicy;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a policy and its `policy-created` audit row in one transaction.
/// Returns the new policy id.
pub async fn insert_policy_audited(
    db: &PgPool,
    p: &NewPolicy,
    actor: &str,
) -> anyhow::Result<Uuid> {
    let mut tx = db.begin().await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO policies \
         (client_name, secret_name, secret_tag, mechanism, outcome, priority, origins, \
          methods, path_prefixes, max_ttl_seconds, max_uses, not_after, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
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
    .bind(&p.created_by)
    .fetch_one(&mut *tx)
    .await?;

    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::POLICY_CREATED,
            client_name: p.client_name.clone(),
            secret_name: p.secret_name.clone(),
            actor: Some(actor.to_owned()),
            detail: Some(serde_json::json!({
                "policy_id": id,
                "mechanism": p.mechanism,
                "outcome": p.outcome,
            })),
            ..Default::default()
        },
    )
    .await?;

    tx.commit().await?;
    Ok(id)
}

/// Delete a policy and write its `policy-deleted` audit row in one
/// transaction. Deletion does not retro-revoke issued grants (they already
/// carry a capped `not_after`). Returns false — with nothing written — when no
/// row matched.
pub async fn delete_policy_audited(db: &PgPool, id: Uuid, actor: &str) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    let deleted: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("DELETE FROM policies WHERE id = $1 RETURNING client_name, secret_name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((client_name, secret_name)) = deleted else {
        tx.rollback().await?;
        return Ok(false);
    };

    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::POLICY_DELETED,
            client_name,
            secret_name,
            actor: Some(actor.to_owned()),
            detail: Some(serde_json::json!({ "policy_id": id })),
            ..Default::default()
        },
    )
    .await?;

    tx.commit().await?;
    Ok(true)
}

/// Outcome of [`update_policy_audited`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePolicyOutcome {
    Updated,
    /// No row with that id (deleted by someone else meanwhile).
    NotFound,
    /// The row is provisioned from config; the UI does not edit it.
    Managed,
}

/// Replace every rule field of an existing, UI-owned policy row and write its
/// `policy-updated` audit row in one transaction. `created_by` is left as it
/// was — the audit row records who made the edit. Like deletion, an edit does
/// not retro-change grants already issued under the old rule.
pub async fn update_policy_audited(
    db: &PgPool,
    id: Uuid,
    p: &NewPolicy,
    actor: &str,
) -> anyhow::Result<UpdatePolicyOutcome> {
    let mut tx = db.begin().await?;
    let before: Option<(bool, String)> =
        sqlx::query_as("SELECT managed_by_config, outcome FROM policies WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((managed, previous_outcome)) = before else {
        tx.rollback().await?;
        return Ok(UpdatePolicyOutcome::NotFound);
    };
    if managed {
        tx.rollback().await?;
        return Ok(UpdatePolicyOutcome::Managed);
    }
    sqlx::query(
        "UPDATE policies SET client_name = $2, secret_name = $3, secret_tag = $4, \
         mechanism = $5, outcome = $6, priority = $7, origins = $8, methods = $9, \
         path_prefixes = $10, max_ttl_seconds = $11, max_uses = $12, not_after = $13 \
         WHERE id = $1",
    )
    .bind(id)
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
    .execute(&mut *tx)
    .await?;

    insert_audit(
        &mut *tx,
        &AuditEvent {
            kind: kinds::POLICY_UPDATED,
            client_name: p.client_name.clone(),
            secret_name: p.secret_name.clone(),
            actor: Some(actor.to_owned()),
            detail: Some(serde_json::json!({
                "policy_id": id,
                "mechanism": p.mechanism,
                "outcome": p.outcome,
                "previous_outcome": previous_outcome,
            })),
            ..Default::default()
        },
    )
    .await?;

    tx.commit().await?;
    Ok(UpdatePolicyOutcome::Updated)
}
