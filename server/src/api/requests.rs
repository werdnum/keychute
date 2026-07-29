//! Access-request handlers: create (idempotent), status, long-poll wait.

use crate::api::error::ApiFailure;
use crate::api::{canonical, status_from_row};
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
/// `grants.max_uses` is an i32 column; anything above this cannot round-trip.
const MAX_USES: u32 = i32::MAX as u32;

/// Validate a create-access-request body and return the normalized
/// constraints to store (canonical path prefixes, uppercased methods,
/// releasing-tier max_uses defaulted to 1). Pure; unit-tested.
/// Bounds on the idempotency key alone. Split out of [`validate_request`]
/// because the create handler must be able to look a retry up — and return
/// the committed request — BEFORE validating fields that are not part of the
/// idempotency identity (see `create`).
pub(crate) fn validate_idempotency_key(req: &CreateAccessRequest) -> Result<(), ApiFailure> {
    if req.idempotency_key.is_empty() {
        return Err(ApiFailure::InvalidRequest("idempotency_key is required"));
    }
    if req.idempotency_key.len() > MAX_IDEM_KEY_BYTES {
        return Err(ApiFailure::RequestTooLarge("idempotency_key too long"));
    }
    Ok(())
}

pub(crate) fn validate_request(req: &CreateAccessRequest) -> Result<Constraints, ApiFailure> {
    validate_idempotency_key(req)?;
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

    // Methods: RFC 9110 token syntax (so `M-SEARCH` and vendor `X-FOO` verbs
    // are accepted, not just letters), normalized to uppercase.
    let mut methods = Vec::with_capacity(c.methods.len());
    for m in &c.methods {
        if !policy::is_valid_http_method(m) {
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
        // `max_uses` is stored in an i32 column: reject out-of-range values
        // here rather than letting a cast wrap them negative (which would
        // exhaust the grant on its first use). Zero is likewise useless.
        match c.max_uses {
            Some(0) => return Err(ApiFailure::InvalidRequest("max_uses must be at least 1")),
            Some(u) if u > MAX_USES => {
                return Err(ApiFailure::InvalidRequest("max_uses is too large"))
            }
            other => other,
        }
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

/// Would this stored row participate in the decision for `req`? Deliberately
/// mirrors `policy::is_applicable`, but reads only the raw columns that always
/// parse (strings and timestamps), so it stays valid for a row whose typed
/// fields are corrupt.
///
/// The mechanism column is compared as text: a value this binary cannot parse
/// is by construction not the requested mechanism, so such a row can never
/// govern this request.
fn row_is_applicable_raw(
    r: &db::PolicyRow,
    client_name: &str,
    req: &policy::RequestedGrant,
    secret_tags: &[String],
    now: chrono::DateTime<Utc>,
) -> bool {
    if r.mechanism != req.mechanism.as_str() {
        return false;
    }
    if let Some(not_after) = r.not_after {
        if not_after <= now {
            return false;
        }
    }
    if let Some(c) = &r.client_name {
        if c != client_name {
            return false;
        }
    }
    match (&r.secret_name, &r.secret_tag) {
        (Some(name), _) => *name == req.secret_name,
        (None, Some(tag)) => secret_tags.iter().any(|t| t == tag),
        (None, None) => true,
    }
}

/// Map store rows into policy-engine inputs.
///
/// Fail closed: a row that is applicable to this request but cannot be parsed
/// makes the whole policy set untrustworthy for this decision, and the request
/// is denied. Skipping it would be a security hole — we cannot tell whether it
/// was a `deny`, and dropping a deny lets a competing auto-approve release the
/// secret it was meant to protect.
///
/// Rows that could not apply to this request (different client, secret,
/// mechanism, or already expired — all decided from columns that cannot be
/// malformed) are dropped with a warning, so one broken unrelated row does not
/// brick every request.
fn policy_inputs(
    client: &db::ClientRow,
    secret: Option<&db::SecretRow>,
    secret_tags: &[String],
    req: &policy::RequestedGrant,
    rows: &[db::PolicyRow],
    now: chrono::DateTime<Utc>,
) -> Result<
    (
        policy::ClientRow,
        Option<policy::SecretRow>,
        Vec<policy::PolicyRow>,
    ),
    ApiFailure,
> {
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
        let applicable = row_is_applicable_raw(r, &client.name, req, secret_tags, now);
        let parsed = (|| {
            let mechanism = Mechanism::from_str_opt(&r.mechanism)?;
            let outcome = policy::Outcome::from_str_opt(&r.outcome)?;
            let origins = serde_json::from_value(r.origins.clone()).ok()?;
            // `methods` and `path_prefixes` are plain text[]: a row written
            // outside the UI can hold values the UI would reject. An invalid
            // prefix silently fails `prefix_matches`, so a DENY row carrying
            // one would stop overlapping and lose to a permissive row —
            // exactly the widening this fail-closed parse exists to prevent.
            // Validate them here so such a row errors instead.
            if !r.methods.iter().all(|m| policy::is_valid_http_method(m)) {
                return None;
            }
            let path_prefixes = r
                .path_prefixes
                .iter()
                .map(|p| policy::paths::canonicalize(p).ok())
                .collect::<Option<Vec<String>>>()?;
            Some((mechanism, outcome, origins, path_prefixes))
        })();
        let Some((mechanism, outcome, origins, path_prefixes)) = parsed else {
            if applicable {
                // Generic reason: never echo the malformed content back.
                tracing::error!(
                    policy_id = %r.id,
                    "unparseable policy row applies to this request; failing closed"
                );
                return Err(ApiFailure::PolicyDenied(
                    "policy set contains an unreadable rule".to_owned(),
                ));
            }
            tracing::warn!(policy_id = %r.id, "skipping unparseable policy row (not applicable)");
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
            // Canonical form, as `prefix_matches` expects.
            path_prefixes,
            max_ttl_seconds: r.max_ttl_seconds.map(|v| v.max(0) as u64),
            max_uses: r.max_uses.map(|v| v.max(0) as u32),
            not_after: r.not_after,
        });
    }
    Ok((client_row, secret_row, out))
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
    // Only the key's own bounds here — it is about to be used as a lookup
    // key. Everything else is validated AFTER the idempotent short-circuit
    // below, so a retry is never rejected on a field that is not part of the
    // idempotency identity: `context.structured` is excluded from the MAC
    // precisely because a rerun captures different machine context, and it
    // would be incoherent to then refuse that rerun for a size limit on it.
    validate_idempotency_key(&req)?;
    let idem_mac = state
        .keyset
        .idem_mac(client.name(), &canonical::canonical_request_payload(&req));

    // Idempotent retry short-circuit, BEFORE validation and policy
    // evaluation: the original response may have been lost, and the retry
    // must recover the committed request even when policy state has degraded
    // since (a row that no longer parses fails `policy_inputs` closed, which
    // would otherwise hide the original request id from its owner forever).
    // The insert's ON CONFLICT branch below stays as the backstop for the
    // concurrent-create race.
    if let Some(row) =
        db::api_ext::get_request_by_idem(&state.db, client.name(), &req.idempotency_key).await?
    {
        if !crypto::ct_eq(&row.idem_mac, &idem_mac) {
            return Err(ApiFailure::IdempotencyKeyReuse);
        }
        let status = status_from_row(&state, &row).await?;
        return Ok((StatusCode::OK, Json(status)).into_response());
    }

    // Genuinely new request: full validation.
    let constraints = validate_request(&req)?;

    // Policy evaluation is pure; run it before the insert so the pending cap
    // can be enforced without creating an orphan row (slight race accepted).
    let secret = db::get_secret_by_name(&state.db, &req.secret_name).await?;
    let secret_tags = match &secret {
        Some(s) => db::get_tags_for_secret(&state.db, s.id).await?,
        None => Vec::new(),
    };
    let policies = db::list_policies(&state.db).await?;
    let requested = policy::RequestedGrant {
        secret_name: req.secret_name.clone(),
        mechanism: req.mechanism,
        constraints: constraints.clone(),
    };
    // Database clock for policy applicability AND (below) every persisted
    // deadline: policy `not_after` rows and the SQL predicates that later
    // enforce grant/request deadlines all live on the DB clock, so evaluating
    // applicability on a skewed process clock could ignore a still-live
    // policy or select an already-expired one.
    let eval_now = db::db_now(&state.db).await?;
    // Fails closed if any row that applies to this request cannot be parsed.
    let (pclient, psecret, prows) = policy_inputs(
        &client.row,
        secret.as_ref(),
        &secret_tags,
        &requested,
        &policies,
        eval_now,
    )?;
    let evaluation = policy::evaluate(
        &pclient,
        psecret.as_ref(),
        &secret_tags,
        &requested,
        &prows,
        eval_now,
    );

    // App-generated id so the encrypted context is AAD-bound to the row.
    let request_id = Uuid::new_v4();
    let context_plaintext: Option<SecretBytes> =
        if req.context.reason.is_empty() && req.context.structured.is_none() {
            None
        } else {
            Some(SecretBytes::new(
                serde_json::to_vec(&req.context)
                    .map_err(|_| ApiFailure::InvalidRequest("invalid context"))?
                    .into_boxed_slice(),
            ))
        };
    // Addendum #19: sealing happens INSIDE the insert transaction, once it
    // holds the KEK shared lock. Sealing here would let the KEK this picked be
    // retired (its zero-reference check passing in the gap) before the row
    // referencing it commits.
    let keyset = &state.keyset;
    let seal_context = context_plaintext.map(|plaintext| -> db::SealFn<'_> {
        Box::new(move || keyset.seal(&plaintext, AadContext::RequestContext { request_id }))
    });

    // Deadlines persisted from this base (request expiry, auto-grant
    // not_after) are enforced by SQL `now()` predicates: same DB-clock base
    // as the policy evaluation above (one fetch, used consistently).
    let now = eval_now;
    let expires_at = now + Duration::seconds(state.config.limits.request_expiry_seconds);
    let new_row = db::NewAccessRequest {
        client_name: client.name().to_owned(),
        secret_name: req.secret_name.clone(),
        mechanism: req.mechanism.as_str().to_owned(),
        constraints: serde_json::to_value(&constraints)
            .map_err(|e| ApiFailure::Internal(e.into()))?,
        expires_at,
        // Cap inherited from the matching standing policy row: the auto-approve
        // path applies it below, and a later human approval reads it off the row.
        policy_not_after: evaluation.policy_not_after,
        idem_client: client.name().to_owned(),
        idem_key: req.idempotency_key.clone(),
        idem_mac: idem_mac.to_vec(),
    };

    // Decide the outcome BEFORE the insert and hand it to the insert
    // transaction, so creation and resolution commit together. A partial
    // failure can then never leave a policy-denied request sitting pending
    // (where an idempotent retry would report it as pending without
    // re-evaluating policy, and the sweeper would ask the operator to approve
    // it).
    let auto_grant = match evaluation.decision {
        policy::Decision::AutoApprove | policy::Decision::NotifyOnly => {
            // The engine only reaches these when the secret exists.
            let Some(secret) = &secret else {
                return Err(ApiFailure::Internal(anyhow::anyhow!(
                    "auto-approve decision without a stored secret"
                )));
            };
            let mut not_after = now + Duration::seconds(constraints.ttl_seconds as i64);
            if let Some(cap) = evaluation.policy_not_after {
                not_after = not_after.min(cap);
            }
            Some(db::GrantParams {
                client_name: client.name().to_owned(),
                secret_name: secret.name.clone(),
                mechanism: req.mechanism.as_str().to_owned(),
                constraints: serde_json::to_value(&constraints)
                    .map_err(|e| ApiFailure::Internal(e.into()))?,
                not_after,
                // Validation rejects anything above i32::MAX; saturate anyway
                // so a future change can never wrap this negative.
                max_uses: constraints
                    .max_uses
                    .map(|u| i32::try_from(u).unwrap_or(i32::MAX)),
                passthrough: None,
            })
        }
        _ => None,
    };
    let resolution = match (&evaluation.decision, &auto_grant) {
        (policy::Decision::Deny { reason }, _) => db::api_ext::InitialResolution::Denied {
            reason,
            resolved_by: "policy",
        },
        (_, Some(grant)) => db::api_ext::InitialResolution::Approved {
            resolved_by: "policy:auto",
            grant,
            // Committed with the approval so a failed immediate FYI push below
            // is durably owed and retried by the sweeper.
            notify_only: matches!(evaluation.decision, policy::Decision::NotifyOnly),
        },
        _ => db::api_ext::InitialResolution::Pending,
    };
    // The pending cap is enforced inside the insert transaction, and only for
    // newly created rows: an idempotent retry of an existing request must
    // never 429. The `request-created` audit row commits with the insert.
    let pending_cap = matches!(evaluation.decision, policy::Decision::RequireApproval)
        .then_some(state.config.limits.max_pending_per_client);
    let (row, created_grant_id) = match db::api_ext::insert_access_request_with_id(
        &state.db,
        request_id,
        &new_row,
        pending_cap,
        &resolution,
        seal_context,
    )
    .await?
    {
        db::api_ext::InsertOutcome::PendingCapExceeded => return Err(ApiFailure::TooManyPending),
        db::api_ext::InsertOutcome::Existing(row) => {
            // Idempotent retry: same MAC returns the existing state (always the
            // decided state, since resolution committed with creation);
            // anything else is a key reuse.
            if !crypto::ct_eq(&row.idem_mac, &idem_mac) {
                return Err(ApiFailure::IdempotencyKeyReuse);
            }
            let status = status_from_row(&state, &row).await?;
            return Ok((StatusCode::OK, Json(status)).into_response());
        }
        db::api_ext::InsertOutcome::Created { row, grant_id } => (row, grant_id),
    };

    match evaluation.decision {
        policy::Decision::Deny { reason } => Err(ApiFailure::PolicyDenied(reason)),
        policy::Decision::AutoApprove | policy::Decision::NotifyOnly => {
            // Row was created already-approved with its grant (see above).
            let notify_only = matches!(evaluation.decision, policy::Decision::NotifyOnly);
            let grant_id = created_grant_id.ok_or_else(|| {
                ApiFailure::Internal(anyhow::anyhow!("approved request created without a grant"))
            })?;
            state.resolve_notify.notify_waiters();
            if notify_only && state.notifier.is_real() {
                // FYI only: the release already happened under a standing
                // policy, so this must NOT read as an approval prompt — the
                // operator would be asked to approve something already done
                // and land on an unactionable resolved request.
                let secret_label = match secret.as_ref().map(|s| s.name.as_str()) {
                    Some(name) => format!("'{name}'"),
                    None => "a not-yet-stored secret".to_owned(),
                };
                let n = crate::notify::release_notification(
                    &state.config.external_url,
                    row.id,
                    client.name(),
                    req.mechanism,
                    &secret_label,
                );
                // Same claim + timeout discipline as the sweeper's FYI retry
                // (which this races): the row committed with `notify_only`, so
                // a failed or timed-out send here is not lost — it stays
                // undelivered and the sweeper retries it.
                let _push_guard = state.push_lock.lock().await;
                if crate::notify::claim_for_fyi_push(&state.db, row.id).await? {
                    match tokio::time::timeout(
                        crate::notify::PUSH_SEND_TIMEOUT,
                        state.notifier.send(&n),
                    )
                    .await
                    {
                        Ok(Ok(())) => db::mark_push_delivered(&state.db, row.id).await?,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "notify-only push failed; sweeper will retry");
                        }
                        Err(_) => {
                            tracing::warn!("notify-only push timed out; sweeper will retry");
                        }
                    }
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
            // No notifier configured: leave push_delivered_at NULL so the row
            // honestly reads "undelivered" (the sweeper also skips it).
            if state.notifier.is_real() {
                // Serialize dedup-check + send: two concurrent identical
                // creates must not both pass the dedup query (single replica
                // by design, so an in-process lock suffices).
                let _push_guard = state.push_lock.lock().await;
                // Same dedup as the sweeper (addendum #10: the key includes
                // the normalized-constraints jsonb). A duplicate push within
                // the window means the operator was just told about an
                // identical pending request; mark this one delivered too so
                // the sweeper does not re-send it seconds later.
                let deduped = db::ui_ext::recent_duplicate_push(
                    &state.db,
                    &row,
                    Utc::now() - Duration::seconds(crate::notify::PUSH_DEDUP_WINDOW_SECONDS),
                )
                .await?;
                if deduped {
                    db::mark_push_delivered(&state.db, row.id).await?;
                } else if !crate::notify::claim_for_push(&state.db, row.id).await? {
                    // Same conditional claim the sweeper's retry uses: the row
                    // committed pending, but the operator may have approved,
                    // denied or let it expire while this push was prepared
                    // (dedup query, notifier lock). Sending now would be an
                    // "approval needed" prompt for an already-decided request.
                    // The claim also bumps `push_attempts`, so the failure
                    // branches below no longer do.
                    tracing::info!(
                        request_id = %row.id,
                        "request resolved before its approval push; not sending"
                    );
                } else {
                    let n = approval_notification(
                        &state,
                        client.name(),
                        req.mechanism,
                        constraints.ttl_seconds,
                        secret.as_ref().map(|s| s.name.as_str()),
                        row.id,
                    );
                    // Bounded like the sweeper's send: `push_lock` is held
                    // across this call, so a notifier without its own timeout
                    // would otherwise wedge every subsequent create that needs
                    // approval. A timed-out push is a FAILED delivery — the row
                    // stays undelivered and the sweeper retries it.
                    match tokio::time::timeout(
                        crate::notify::PUSH_SEND_TIMEOUT,
                        state.notifier.send(&n),
                    )
                    .await
                    {
                        Ok(Ok(())) => db::mark_push_delivered(&state.db, row.id).await?,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "approval push failed; sweeper will retry");
                        }
                        Err(_) => {
                            tracing::warn!(
                                request_id = %row.id,
                                timeout_seconds = crate::notify::PUSH_SEND_TIMEOUT.as_secs(),
                                "approval push timed out; sweeper will retry"
                            );
                        }
                    }
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
    fn method_token_syntax_accepted() {
        // RFC 9110 tokens, not just letters.
        let mut req = base_request(Mechanism::Brokered);
        req.constraints.methods = vec!["m-search".into(), "X-FOO".into()];
        let c = validate_request(&req).unwrap();
        assert_eq!(c.methods, vec!["M-SEARCH", "X-FOO"]);

        for bad in ["bad method", "", "GET GET", "GET/1"] {
            let mut req = base_request(Mechanism::Brokered);
            req.constraints.methods = vec![bad.into()];
            assert_eq!(
                code(validate_request(&req).unwrap_err()),
                "invalid-request",
                "expected reject: {bad:?}"
            );
        }
    }

    #[test]
    fn brokered_max_uses_range_is_enforced() {
        let mut req = base_request(Mechanism::Brokered);
        req.constraints.max_uses = Some(u32::MAX);
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::Brokered);
        req.constraints.max_uses = Some(MAX_USES + 1);
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        let mut req = base_request(Mechanism::Brokered);
        req.constraints.max_uses = Some(0);
        assert_eq!(code(validate_request(&req).unwrap_err()), "invalid-request");

        // The largest storable value survives the i32 round-trip unchanged.
        let mut req = base_request(Mechanism::Brokered);
        req.constraints.max_uses = Some(MAX_USES);
        let c = validate_request(&req).unwrap();
        assert_eq!(c.max_uses, Some(MAX_USES));
        assert_eq!(
            c.max_uses.map(|u| i32::try_from(u).unwrap_or(i32::MAX)),
            Some(i32::MAX)
        );
    }

    // ---------- policy_inputs: fail closed ----------

    fn db_client() -> db::ClientRow {
        db::ClientRow {
            id: Uuid::new_v4(),
            name: "family-assistant".into(),
            max_tier: Tier::Direct.as_int(),
            mechanisms: vec!["brokered".into()],
            auth_kind: "api-token".into(),
            api_token_sha256: None,
            sa_audience: None,
            sa_subject: None,
            enabled: true,
            may_store_secrets: false,
        }
    }

    fn db_policy_row() -> db::PolicyRow {
        db::PolicyRow {
            id: Uuid::new_v4(),
            client_name: None,
            secret_name: None,
            secret_tag: None,
            mechanism: "brokered".into(),
            outcome: "deny".into(),
            priority: 0,
            origins: serde_json::json!([]),
            methods: vec![],
            path_prefixes: vec![],
            max_ttl_seconds: None,
            max_uses: None,
            not_after: None,
            created_by: "test".into(),
            created_at: Utc::now(),
        }
    }

    fn requested() -> policy::RequestedGrant {
        let req = base_request(Mechanism::Brokered);
        policy::RequestedGrant {
            secret_name: req.secret_name.clone(),
            mechanism: req.mechanism,
            constraints: validate_request(&req).unwrap(),
        }
    }

    #[test]
    fn unparseable_applicable_row_fails_closed() {
        // Malformed origins on a row that applies to this request: the row
        // could be a deny, so the request must be refused, not silently
        // evaluated against the remaining (possibly permissive) rows.
        let mut bad = db_policy_row();
        bad.origins = serde_json::json!({"not": "an origin list"});
        let err =
            policy_inputs(&db_client(), None, &[], &requested(), &[bad], Utc::now()).unwrap_err();
        assert!(
            matches!(err, ApiFailure::PolicyDenied(_)),
            "expected PolicyDenied, got {err:?}"
        );

        // Same for an unreadable outcome.
        let mut bad = db_policy_row();
        bad.outcome = "auto-aprove".into();
        assert!(matches!(
            policy_inputs(&db_client(), None, &[], &requested(), &[bad], Utc::now()).unwrap_err(),
            ApiFailure::PolicyDenied(_)
        ));
    }

    #[test]
    fn unparseable_inapplicable_row_is_skipped() {
        let good = db_policy_row();
        let good_id = good.id;

        // Broken rows that cannot govern this request: other client, other
        // secret, other mechanism, already expired.
        let mut other_client = db_policy_row();
        other_client.client_name = Some("someone-else".into());
        other_client.origins = serde_json::json!(42);

        let mut other_secret = db_policy_row();
        other_secret.secret_name = Some("other-secret".into());
        other_secret.origins = serde_json::json!(42);

        let mut other_tag = db_policy_row();
        other_tag.secret_tag = Some("untagged".into());
        other_tag.origins = serde_json::json!(42);

        let mut other_mech = db_policy_row();
        other_mech.mechanism = "mechanism-from-the-future".into();
        other_mech.origins = serde_json::json!(42);

        let mut expired = db_policy_row();
        expired.not_after = Some(Utc::now() - Duration::hours(1));
        expired.origins = serde_json::json!(42);

        let (_, _, rows) = policy_inputs(
            &db_client(),
            None,
            &[],
            &requested(),
            &[
                other_client,
                other_secret,
                other_tag,
                other_mech,
                expired,
                good,
            ],
            Utc::now(),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, good_id);
    }

    #[test]
    fn ttl_human_formats() {
        assert_eq!(ttl_human(3600), "1h");
        assert_eq!(ttl_human(7200), "2h");
        assert_eq!(ttl_human(5400), "90m");
        assert_eq!(ttl_human(45), "45s");
    }
}
