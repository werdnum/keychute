//! Access-request handlers: create (idempotent), status, long-poll wait.

use crate::api::error::ApiFailure;
use crate::api::{canonical, status_from_row};
use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::authn::client::{authenticate_client, AuthedClient};
use crate::crypto::{self, AadContext, SecretBytes};
use crate::db;
use crate::notify::Notification;
use crate::policy;
use crate::state::{AppState, SlotKind};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use keychute_types::{Constraints, CreateAccessRequest, Mechanism, RequestState, Tier};
use serde::Deserialize;
use uuid::Uuid;

/// Bounds pinned by addendum #18.
const MAX_IDEM_KEY_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 4 * 1024;
const MAX_STRUCTURED_BYTES: usize = 16 * 1024;
const MAX_CONSTRAINT_ENTRIES: usize = 32;
const MAX_TTL_SECONDS: u64 = 30 * 24 * 3600;

/// Validate a create-access-request body and return the normalized
/// constraints to store (canonical path prefixes, uppercased methods,
/// releasing-tier max_uses defaulted to 1). Pure; unit-tested.
pub(crate) fn validate_request(req: &CreateAccessRequest) -> Result<Constraints, ApiFailure> {
    if req.idempotency_key.is_empty() {
        return Err(ApiFailure::InvalidRequest("idempotency_key is required"));
    }
    if req.idempotency_key.len() > MAX_IDEM_KEY_BYTES {
        return Err(ApiFailure::RequestTooLarge("idempotency_key too long"));
    }
    if req.secret_name.is_empty() || req.secret_name.len() > 256 {
        return Err(ApiFailure::InvalidRequest("invalid secret_name"));
    }
    if req.context.reason.len() > MAX_REASON_BYTES {
        return Err(ApiFailure::RequestTooLarge("context.reason too long"));
    }
    if let Some(structured) = &req.context.structured {
        let serialized = serde_json::to_vec(structured)
            .map_err(|_| ApiFailure::InvalidRequest("invalid structured context"))?;
        if serialized.len() > MAX_STRUCTURED_BYTES {
            return Err(ApiFailure::RequestTooLarge("context.structured too large"));
        }
    }
    let c = &req.constraints;
    if c.origins.len() > MAX_CONSTRAINT_ENTRIES
        || c.methods.len() > MAX_CONSTRAINT_ENTRIES
        || c.path_prefixes.len() > MAX_CONSTRAINT_ENTRIES
    {
        return Err(ApiFailure::RequestTooLarge("too many constraint entries"));
    }
    if c.ttl_seconds < 1 || c.ttl_seconds > MAX_TTL_SECONDS {
        return Err(ApiFailure::InvalidRequest(
            "ttl_seconds must be between 1 and 30 days",
        ));
    }

    // Methods: plausible HTTP tokens, normalized to uppercase.
    let mut methods = Vec::with_capacity(c.methods.len());
    for m in &c.methods {
        if m.is_empty() || m.len() > 32 || !m.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return Err(ApiFailure::InvalidRequest("invalid method"));
        }
        methods.push(m.to_ascii_uppercase());
    }

    // Path prefixes must each canonicalize.
    let mut prefixes = Vec::with_capacity(c.path_prefixes.len());
    for p in &c.path_prefixes {
        let canonical = policy::paths::canonicalize(p)
            .map_err(|_| ApiFailure::InvalidRequest("invalid path prefix"))?;
        prefixes.push(canonical);
    }

    let max_uses = if req.mechanism == Mechanism::Brokered {
        if c.origins.len() != 1 {
            return Err(ApiFailure::InvalidRequest(
                "brokered requests must name exactly one origin",
            ));
        }
        if methods.is_empty() {
            return Err(ApiFailure::InvalidRequest(
                "brokered requests must name at least one method",
            ));
        }
        c.max_uses
    } else {
        // Releasing tiers: default 1, and no more than 1 in v1.
        match c.max_uses {
            None => Some(1),
            Some(1) => Some(1),
            Some(_) => {
                return Err(ApiFailure::InvalidRequest(
                    "releasing-tier requests may not exceed max_uses = 1",
                ))
            }
        }
    };

    Ok(Constraints {
        origins: c.origins.clone(),
        methods,
        path_prefixes: prefixes,
        ttl_seconds: c.ttl_seconds,
        max_uses,
    })
}

/// Map store rows into policy-engine inputs. Rows that fail to parse are
/// skipped (logged); a skipped row can only make the outcome more restrictive
/// for non-deny rows and is never silently widened.
fn policy_inputs(
    client: &db::ClientRow,
    secret: Option<&db::SecretRow>,
    rows: &[db::PolicyRow],
) -> (
    policy::ClientRow,
    Option<policy::SecretRow>,
    Vec<policy::PolicyRow>,
) {
    let client_row = policy::ClientRow {
        name: client.name.clone(),
        enabled: client.enabled,
        max_tier: Tier::from_int(client.max_tier).unwrap_or(Tier::Brokered),
        allowed_mechanisms: client
            .mechanisms
            .iter()
            .filter_map(|m| Mechanism::from_str_opt(m))
            .collect(),
    };
    let secret_row = secret.map(|s| policy::SecretRow {
        name: s.name.clone(),
        enabled: s.enabled,
        max_tier: Tier::from_int(s.max_tier).unwrap_or(Tier::Brokered),
    });
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let (Some(mechanism), Some(outcome)) = (
            Mechanism::from_str_opt(&r.mechanism),
            policy::Outcome::from_str_opt(&r.outcome),
        ) else {
            tracing::warn!(policy_id = %r.id, "skipping unparseable policy row");
            continue;
        };
        let Ok(origins) = serde_json::from_value(r.origins.clone()) else {
            tracing::warn!(policy_id = %r.id, "skipping policy row with malformed origins");
            continue;
        };
        out.push(policy::PolicyRow {
            id: r.id,
            client_name: r.client_name.clone(),
            secret_name: r.secret_name.clone(),
            secret_tag: r.secret_tag.clone(),
            mechanism,
            outcome,
            priority: r.priority,
            origins,
            methods: r.methods.clone(),
            path_prefixes: r.path_prefixes.clone(),
            max_ttl_seconds: r.max_ttl_seconds.map(|v| v.max(0) as u64),
            max_uses: r.max_uses.map(|v| v.max(0) as u32),
            not_after: r.not_after,
        });
    }
    (client_row, secret_row, out)
}

/// Human-friendly TTL for push messages ("1h", "90m", "45s").
pub(crate) fn ttl_human(seconds: u64) -> String {
    if seconds.is_multiple_of(3600) {
        format!("{}h", seconds / 3600)
    } else if seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{}s", seconds)
    }
}

/// Approval push. Server vocabulary only: client name, TTL, mechanism, tier
/// label, and the secret name only when it refers to a stored secret
/// (addendum #5).
fn approval_notification(
    state: &AppState,
    client_name: &str,
    mechanism: Mechanism,
    ttl_seconds: u64,
    secret_stored: Option<&str>,
    request_id: Uuid,
) -> Notification {
    let secret_label = match secret_stored {
        Some(name) => format!("'{name}'"),
        None => "a not-yet-stored secret".to_owned(),
    };
    Notification {
        title: "Keychute approval needed".to_owned(),
        message: format!(
            "{client_name} requests {} of {} access ({}) using {secret_label}",
            ttl_human(ttl_seconds),
            mechanism.as_str(),
            mechanism.tier().human_label(),
        ),
        url: Some(format!(
            "{}/ui/requests/{request_id}",
            state.config.external_url.trim_end_matches('/')
        )),
        url_title: Some("Review request".to_owned()),
    }
}

/// POST /v1/access-requests
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;

    let req: CreateAccessRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiFailure::InvalidRequest("malformed request body"))?;
    let constraints = validate_request(&req)?;
    let idem_mac = state
        .keyset
        .idem_mac(client.name(), &canonical::canonical_request_payload(&req));

    // Policy evaluation is pure; run it before the insert so the pending cap
    // can be enforced without creating an orphan row (slight race accepted).
    let secret = db::get_secret_by_name(&state.db, &req.secret_name).await?;
    let secret_tags = match &secret {
        Some(s) => db::get_tags_for_secret(&state.db, s.id).await?,
        None => Vec::new(),
    };
    let policies = db::list_policies(&state.db).await?;
    let (pclient, psecret, prows) = policy_inputs(&client.row, secret.as_ref(), &policies);
    let requested = policy::RequestedGrant {
        secret_name: req.secret_name.clone(),
        mechanism: req.mechanism,
        constraints: constraints.clone(),
    };
    let evaluation = policy::evaluate(
        &pclient,
        psecret.as_ref(),
        &secret_tags,
        &requested,
        &prows,
        Utc::now(),
    );

    if matches!(evaluation.decision, policy::Decision::RequireApproval) {
        let pending = db::count_pending_for_client(&state.db, client.name()).await?;
        if pending >= state.config.limits.max_pending_per_client {
            return Err(ApiFailure::TooManyPending);
        }
    }

    // App-generated id so the encrypted context is AAD-bound to the row.
    let request_id = Uuid::new_v4();
    let sealed_context = if req.context.reason.is_empty() && req.context.structured.is_none() {
        None
    } else {
        let plaintext: SecretBytes = SecretBytes::new(
            serde_json::to_vec(&req.context)
                .map_err(|_| ApiFailure::InvalidRequest("invalid context"))?
                .into_boxed_slice(),
        );
        Some(
            state
                .keyset
                .seal(&plaintext, AadContext::RequestContext { request_id })
                .map_err(|e| ApiFailure::Internal(e.into()))?,
        )
    };
    let (ctx_ct, ctx_nonce, ctx_dek, ctx_kek) = match sealed_context {
        Some(s) => (
            Some(s.ciphertext),
            Some(s.nonce),
            Some(s.wrapped_dek),
            Some(s.kek_id),
        ),
        None => (None, None, None, None),
    };

    let now = Utc::now();
    let expires_at = now + Duration::seconds(state.config.limits.request_expiry_seconds);
    let new_row = db::NewAccessRequest {
        client_name: client.name().to_owned(),
        secret_name: req.secret_name.clone(),
        mechanism: req.mechanism.as_str().to_owned(),
        constraints: serde_json::to_value(&constraints)
            .map_err(|e| ApiFailure::Internal(e.into()))?,
        context_ciphertext: ctx_ct,
        context_nonce: ctx_nonce,
        context_wrapped_dek: ctx_dek,
        context_kek_id: ctx_kek,
        expires_at,
        idem_client: client.name().to_owned(),
        idem_key: req.idempotency_key.clone(),
        idem_mac: idem_mac.to_vec(),
    };
    let inserted =
        db::api_ext::insert_access_request_with_id(&state.db, request_id, &new_row).await?;

    if !inserted.created {
        // Idempotent retry: same MAC returns the existing state; anything
        // else is a key reuse.
        if !crypto::ct_eq(&inserted.row.idem_mac, &idem_mac) {
            return Err(ApiFailure::IdempotencyKeyReuse);
        }
        let status = status_from_row(&state, &inserted.row).await?;
        return Ok((StatusCode::OK, Json(status)).into_response());
    }
    let row = inserted.row;

    insert_audit(
        &state.db,
        &AuditEvent {
            kind: kinds::REQUEST_CREATED,
            request_id: Some(row.id),
            client_name: Some(client.name().to_owned()),
            secret_name: Some(req.secret_name.clone()),
            detail: Some(serde_json::json!({ "mechanism": req.mechanism.as_str() })),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| ApiFailure::Internal(e.into()))?;

    match evaluation.decision {
        policy::Decision::Deny { reason } => {
            db::resolve_deny(&state.db, row.id, "policy", &reason).await?;
            Err(ApiFailure::PolicyDenied(reason))
        }
        policy::Decision::AutoApprove | policy::Decision::NotifyOnly => {
            // The engine only reaches these when the secret exists.
            let Some(secret) = &secret else {
                return Err(ApiFailure::Internal(anyhow::anyhow!(
                    "auto-approve decision without a stored secret"
                )));
            };
            let notify_only = matches!(evaluation.decision, policy::Decision::NotifyOnly);
            let mut not_after = now + Duration::seconds(constraints.ttl_seconds as i64);
            if let Some(cap) = evaluation.policy_not_after {
                not_after = not_after.min(cap);
            }
            let grant = db::GrantParams {
                client_name: client.name().to_owned(),
                secret_name: secret.name.clone(),
                mechanism: req.mechanism.as_str().to_owned(),
                constraints: serde_json::to_value(&constraints)
                    .map_err(|e| ApiFailure::Internal(e.into()))?,
                not_after,
                max_uses: constraints.max_uses.map(|u| u as i32),
                passthrough: None,
            };
            let grant_id = db::resolve_approve(&state.db, row.id, "policy:auto", &grant)
                .await?
                .ok_or_else(|| {
                    ApiFailure::Internal(anyhow::anyhow!("freshly created request not pending"))
                })?;
            state.resolve_notify.notify_waiters();
            if notify_only {
                // FYI only: the release proceeds regardless of delivery.
                let n = approval_notification(
                    &state,
                    client.name(),
                    req.mechanism,
                    constraints.ttl_seconds,
                    Some(secret.name.as_str()),
                    row.id,
                );
                if let Err(e) = state.notifier.send(&n).await {
                    tracing::warn!(error = %e, "notify-only push failed");
                }
            }
            let status = keychute_types::AccessRequestStatus {
                request_id: row.id,
                state: RequestState::Approved,
                grant_id: Some(grant_id),
                deny_reason: None,
                expires_at: row.expires_at,
            };
            Ok((StatusCode::CREATED, Json(status)).into_response())
        }
        policy::Decision::RequireApproval => {
            let n = approval_notification(
                &state,
                client.name(),
                req.mechanism,
                constraints.ttl_seconds,
                secret.as_ref().map(|s| s.name.as_str()),
                row.id,
            );
            match state.notifier.send(&n).await {
                Ok(()) => db::mark_push_delivered(&state.db, row.id).await?,
                Err(e) => {
                    tracing::warn!(error = %e, "approval push failed; sweeper will retry");
                    db::increment_push_attempts(&state.db, row.id).await?;
                }
            }
            let status = keychute_types::AccessRequestStatus {
                request_id: row.id,
                state: RequestState::Pending,
                grant_id: None,
                deny_reason: None,
                expires_at: row.expires_at,
            };
            Ok((StatusCode::CREATED, Json(status)).into_response())
        }
    }
}

/// Fetch a request enforcing ownership (mismatch → 404, addendum #1).
async fn owned_request(
    state: &AppState,
    client: &AuthedClient,
    id: Uuid,
) -> Result<db::AccessRequestRow, ApiFailure> {
    let row = db::get_request(&state.db, id)
        .await?
        .ok_or(ApiFailure::NotFound)?;
    if row.client_name != client.name() {
        return Err(ApiFailure::NotFound);
    }
    Ok(row)
}

/// GET /v1/access-requests/{id}
pub async fn status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;
    let row = owned_request(&state, &client, id).await?;
    let status = status_from_row(&state, &row).await?;
    Ok(Json(status).into_response())
}

#[derive(Deserialize)]
pub struct WaitParams {
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// GET /v1/access-requests/{id}/wait?timeout_seconds=N — long-poll until the
/// request resolves or the (capped) timeout elapses; may return pending.
pub async fn wait(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<WaitParams>,
    headers: HeaderMap,
) -> Result<Response, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;
    let row = owned_request(&state, &client, id).await?;

    let max = state.config.limits.wait_max_seconds;
    let timeout = params.timeout_seconds.unwrap_or(max).min(max);

    // RAII slot guard: drops on every return path.
    let _slot = state
        .try_take_slot(client.name(), SlotKind::Wait)
        .ok_or(ApiFailure::TooManyWaits)?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
    let mut row = row;
    loop {
        if row.state != "pending" {
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let tick = std::cmp::min(deadline - now, std::time::Duration::from_secs(1));
        tokio::select! {
            _ = state.resolve_notify.notified() => {}
            _ = tokio::time::sleep(tick) => {}
        }
        row = owned_request(&state, &client, id).await?;
    }
    let status = status_from_row(&state, &row).await?;
    Ok(Json(status).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keychute_types::{Origin, RequestContext};

    fn base_request(mechanism: Mechanism) -> CreateAccessRequest {
        CreateAccessRequest {
            idempotency_key: "key-1".into(),
            secret_name: "example".into(),
            mechanism,
            constraints: Constraints {
                origins: vec![Origin::parse("api.example.com").unwrap()],
                methods: vec!["get".into(), "POST".into()],
                path_prefixes: vec!["/v1/things".into()],
                ttl_seconds: 3600,
                max_uses: None,
            },
            context: RequestContext::default(),
        }
    }

    fn code(f: ApiFailure) -> &'static str {
        match f {
            ApiFailure::InvalidRequest(_) => "invalid-request",
            ApiFailure::RequestTooLarge(_) => "request-too-large",
            _ => "other",
        }
    }

    #[test]
    fn brokered_requires_exactly_one_origin_and_a_method() {
        let mut req = base_request(Mechanism::Brokered);
        req.constraints.origins.clear();
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::Brokered);
        req.constraints
            .origins
            .push(Origin::parse("two.example.com").unwrap());
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::Brokered);
        req.constraints.methods.clear();
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        // Valid brokered request normalizes methods to uppercase and may be
        // multi-use (max_uses stays None).
        let c = validate_request(&base_request(Mechanism::Brokered)).unwrap();
        assert_eq!(c.methods, vec!["GET", "POST"]);
        assert_eq!(c.max_uses, None);
    }

    #[test]
    fn releasing_max_uses_defaults_to_one_and_caps_at_one() {
        let c = validate_request(&base_request(Mechanism::CliRead)).unwrap();
        assert_eq!(c.max_uses, Some(1));

        let mut req = base_request(Mechanism::CliRead);
        req.constraints.max_uses = Some(2);
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::CliRead);
        req.constraints.max_uses = Some(1);
        assert_eq!(validate_request(&req).unwrap().max_uses, Some(1));
    }

    #[test]
    fn ttl_bounds() {
        let mut req = base_request(Mechanism::CliRead);
        req.constraints.ttl_seconds = 0;
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");
        req.constraints.ttl_seconds = MAX_TTL_SECONDS + 1;
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");
        req.constraints.ttl_seconds = MAX_TTL_SECONDS;
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn path_prefixes_must_canonicalize() {
        let mut req = base_request(Mechanism::Brokered);
        req.constraints.path_prefixes = vec!["/ok/%2e%2e/../nope".into()];
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");
        req.constraints.path_prefixes = vec!["/a%20b".into()];
        let c = validate_request(&req).unwrap();
        assert_eq!(c.path_prefixes, vec!["/a b"]);
    }

    #[test]
    fn size_bounds() {
        let mut req = base_request(Mechanism::CliRead);
        req.idempotency_key = "k".repeat(129);
        assert_eq!(
            code(validate_request(&req).unwrap_err()),
            "request-too-large"
        );

        let mut req = base_request(Mechanism::CliRead);
        req.idempotency_key = String::new();
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::CliRead);
        req.context.reason = "r".repeat(MAX_REASON_BYTES + 1);
        assert_eq!(
            code(validate_request(&req).unwrap_err()),
            "request-too-large"
        );

        let mut req = base_request(Mechanism::CliRead);
        req.context.structured = Some(serde_json::json!("x".repeat(MAX_STRUCTURED_BYTES)));
        assert_eq!(
            code(validate_request(&req).unwrap_err()),
            "request-too-large"
        );

        let mut req = base_request(Mechanism::Brokered);
        req.constraints.methods = (0..33).map(|_| "GET".to_owned()).collect();
        assert_eq!(
            code(validate_request(&req).unwrap_err()),
            "request-too-large"
        );
    }

    #[test]
    fn ttl_human_formats() {
        assert_eq!(ttl_human(3600), "1h");
        assert_eq!(ttl_human(7200), "2h");
        assert_eq!(ttl_human(5400), "90m");
        assert_eq!(ttl_human(45), "45s");
    }
}
