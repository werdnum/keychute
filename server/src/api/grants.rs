//! Grant endpoints: metadata lookup, and the single logical release with
//! idempotent replay.

use crate::api::error::ApiFailure;
use crate::api::{owned_grant, revalidate_grant};
use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::authn::client::authenticate_client;
use crate::crypto::{AadContext, SecretBytes};
use crate::db;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use keychute_types::{
    Constraints, GrantInfo, Mechanism, ReadGrantRequest, ReadGrantResponse, SecretEncoding,
};
use secrecy::ExposeSecret;
use uuid::Uuid;

/// `GET /v1/grants/{id}` — non-secret metadata about a grant the caller owns.
///
/// Exists because a client that comes back to a grant later cannot otherwise
/// see what it actually holds. Two things make that a correctness problem, not
/// a convenience one:
///
/// * The proxy takes the upstream origin from the GRANT, never from the
///   caller's request URL. A caller that reuses a grant against a different
///   origin gets its request delivered to the approved one — silently, with
///   whatever side effect it carries. Only the grant can settle where a call
///   is really going.
/// * Approval may NARROW `ttl_seconds`/`max_uses`, so what the client asked
///   for is not what it got.
///
/// Read-only and owner-scoped (a grant belonging to another client is 404, like
/// every other grant route). Deliberately does NOT revalidate or touch use
/// accounting: it reports the row, including a revoked or expired one, because
/// "this grant is dead" is precisely what a caller needs to learn here rather
/// than at the moment it applies a side effect.
pub async fn info(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<GrantInfo>, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;
    let grant = owned_grant(&state, &client, id).await?;
    let mechanism = Mechanism::from_str_opt(&grant.mechanism)
        .ok_or_else(|| ApiFailure::Internal(anyhow::anyhow!("unknown grant mechanism")))?;
    let mut constraints: Constraints = serde_json::from_value(grant.constraints.clone())
        .map_err(|e| ApiFailure::Internal(e.into()))?;
    // `grant.constraints` is the REQUESTED json, stored verbatim at approval;
    // an operator who narrows the TTL or use count changes only the
    // `not_after` and `max_uses` columns (see `ui::approve`). Returning that
    // json untouched would report the request back as though it were the
    // grant — the exact confusion this endpoint exists to remove — so the two
    // narrowable fields are replaced with what was actually granted before
    // anything leaves. Everything else in the json (origins, methods, path
    // prefixes) is not narrowable and is already the granted truth.
    constraints.max_uses = grant.max_uses.map(|v| v.max(0) as u32);
    // Rounded, not truncated: `not_after` is computed from a clock read taken
    // a hair before the row's `created_at`, so a 600s grant spans 599.99s and
    // truncation would report 599 — a value nobody chose, and one that reads
    // as an off-by-one to anyone comparing it against what they asked for.
    constraints.ttl_seconds = {
        let millis = (grant.not_after - grant.created_at)
            .num_milliseconds()
            .max(0);
        ((millis + 500) / 1000) as u64
    };
    Ok(Json(GrantInfo {
        grant_id: grant.id,
        mechanism,
        constraints,
        not_after: grant.not_after,
        // The column is i32 and never negative in practice; clamp rather than
        // surface a negative use budget if it ever were.
        max_uses: grant.max_uses.map(|v| v.max(0) as u32),
        use_count: grant.use_count.max(0) as u32,
        revoked: grant.revoked,
    }))
}

/// Decrypt a grant's passthrough payload. Any failure — including a nulled
/// payload or a process restart under the ephemeral KEK — is `payload-lost`.
///
/// The process-local ephemeral KEK is the only key a passthrough payload is
/// ever wrapped under ([`db::PassthroughPayload`], DESIGN §5), so there is no
/// keyset branch here: the grants table records no `kek_id`, and a row whose
/// `passthrough_ephemeral` is somehow false could only be decrypted by guessing
/// a keyset key. Guessing would also mean the payload had been sealed outside
/// the writing transaction's KEK shared lock. Such a row cannot be written by
/// this code; if one existed it would be reported `payload-lost`, which is the
/// same fail-closed answer a restart gives.
fn open_passthrough(state: &AppState, grant: &db::GrantRow) -> Result<SecretBytes, ApiFailure> {
    let (Some(ct), Some(nonce), Some(dek)) = (
        &grant.passthrough_ciphertext,
        &grant.passthrough_nonce,
        &grant.passthrough_wrapped_dek,
    ) else {
        return Err(ApiFailure::PayloadLost);
    };
    if !grant.passthrough_ephemeral {
        return Err(ApiFailure::PayloadLost);
    }
    state
        .ephemeral_kek
        .open(
            ct,
            nonce,
            dek,
            AadContext::GrantPassthrough { grant_id: grant.id },
        )
        .map_err(|_| ApiFailure::PayloadLost)
}

fn open_secret_version(
    state: &AppState,
    row: &db::SecretVersionRow,
) -> Result<SecretBytes, ApiFailure> {
    state
        .keyset
        .open(
            &row.ciphertext,
            &row.nonce,
            &row.wrapped_dek,
            &row.kek_id,
            AadContext::SecretVersion {
                secret_id: row.secret_id,
                version: row.version,
            },
        )
        .map_err(|e| ApiFailure::Internal(e.into()))
}

/// POST /v1/grants/{id}/read
pub async fn read(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;
    let req: ReadGrantRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiFailure::InvalidRequest("malformed request body"))?;
    if req.idempotency_key.is_empty() {
        return Err(ApiFailure::InvalidRequest("idempotency_key is required"));
    }
    // 160 leaves headroom over the request-key cap (128) for client-derived
    // prefixes such as the CLI's `cli-` (which itself enforces <= 124 bytes).
    if req.idempotency_key.len() > 160 {
        return Err(ApiFailure::RequestTooLarge("idempotency_key too long"));
    }

    let grant = owned_grant(&state, &client, id).await?;
    let mechanism =
        Mechanism::from_str_opt(&grant.mechanism).ok_or(ApiFailure::RevalidationFailed)?;
    if !mechanism.is_releasing() {
        return Err(ApiFailure::WrongMechanism);
    }
    let secret = revalidate_grant(&state, &grant).await?;

    // Revocation/expiry outrank payload state: a revoked grant purges its
    // passthrough immediately, and must report "revoked", not "payload-lost".
    // DB clock, not process clock — the authoritative deadline is SQL `now()`.
    let dead: bool =
        sqlx::query_scalar("SELECT revoked OR now() >= not_after FROM grants WHERE id = $1")
            .bind(grant.id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| ApiFailure::Internal(e.into()))?
            .unwrap_or(true);
    if dead {
        return Err(ApiFailure::GrantExpired);
    }

    // Resolve the payload source BEFORE use-accounting so the released
    // version id is pinned into replay state.
    enum Source {
        Passthrough,
        /// Was a passthrough grant, but the payload is gone (purged; a restart
        /// additionally makes decryption impossible).
        PassthroughGone,
        Stored(db::SecretVersionRow),
    }
    let (source, version_id) = if grant.passthrough_ciphertext.is_some() {
        (Source::Passthrough, grant.id)
    } else if grant.passthrough_ephemeral {
        // Deliberately NOT an early return: use-accounting has to establish
        // exhaustion first. Once a single-use passthrough has been consumed
        // and its replay window has closed, the sweeper nulls the ciphertext
        // by design — reporting "payload-lost" here would tell the caller the
        // secret was never released (and push the CLI onto its re-approval
        // exit code) when in fact it already was. `begin_grant_use` sees
        // `use_count == max_uses` and returns `grant-exhausted`; only when a
        // use is genuinely still available does this become "payload-lost",
        // which is the real restart/loss case.
        (Source::PassthroughGone, grant.id)
    } else {
        let secret = secret.as_ref().ok_or(ApiFailure::PayloadLost)?;
        let version = db::get_secret_version(&state.db, secret.id, secret.current_version)
            .await?
            .ok_or(ApiFailure::PayloadLost)?;
        let vid = version.id;
        (Source::Stored(version), vid)
    };

    let outcome = db::begin_grant_use(
        &state.db,
        grant.id,
        Some(&req.idempotency_key),
        Some(version_id),
        kinds::RELEASE_ATTEMPT,
        state.config.limits.replay_window_seconds,
        None,
    )
    .await?;

    let (plaintext, released_version_id, grant_row) = match outcome {
        db::GrantUse::NotFound => return Err(ApiFailure::NotFound),
        db::GrantUse::ExpiredOrRevoked => return Err(ApiFailure::GrantExpired),
        db::GrantUse::Exhausted => return Err(ApiFailure::GrantExhausted),
        db::GrantUse::FirstUse { grant } => {
            let pt = match &source {
                Source::Passthrough => open_passthrough(&state, &grant)?,
                Source::PassthroughGone => return Err(ApiFailure::PayloadLost),
                Source::Stored(version) => open_secret_version(&state, version)?,
            };
            (pt, version_id, grant)
        }
        db::GrantUse::Replay {
            grant,
            secret_version_id,
            passthrough,
        } => {
            if passthrough {
                let pt = open_passthrough(&state, &grant)?;
                (pt, grant.id, grant)
            } else {
                let pinned = secret_version_id.ok_or(ApiFailure::PayloadLost)?;
                let version = db::get_secret_version_by_id(&state.db, pinned)
                    .await?
                    .ok_or(ApiFailure::PayloadLost)?;
                let pt = open_secret_version(&state, &version)?;
                (pt, pinned, grant)
            }
        }
    };

    // Encode the payload (confined expose_secret site: grant-read response).
    let bytes = plaintext.expose_secret();
    let (secret_str, encoding) = match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_owned(), SecretEncoding::Utf8),
        Err(_) => (
            base64::engine::general_purpose::STANDARD.encode(bytes),
            SecretEncoding::Base64,
        ),
    };
    let response_body = ReadGrantResponse {
        secret: secret_str,
        encoding,
        secret_version_id: released_version_id,
    };

    // Best-effort and DETACHED, like the proxy path's completion audit:
    // `begin_grant_use` committed the use and the write-ahead `release-attempt`
    // row above. Failing or even briefly delaying the response here is worse
    // than a missing completion row — a stalled insert could hold the secret
    // past a short replay window, so the caller's same-key retry of a lost
    // response would find `grant-exhausted` with nothing released.
    let audit_db = state.db.clone();
    let audit_event = AuditEvent {
        kind: kinds::RELEASE_COMPLETED,
        request_id: Some(grant_row.request_id),
        grant_id: Some(grant_row.id),
        client_name: Some(grant_row.client_name.clone()),
        secret_name: Some(grant_row.secret_name.clone()),
        secret_version_id: Some(released_version_id),
        status: Some(200),
        ..Default::default()
    };
    let audit_grant_id = grant_row.id;
    tokio::spawn(async move {
        let audited = tokio::time::timeout(
            crate::proxy::COMPLETION_AUDIT_TIMEOUT,
            insert_audit(&audit_db, &audit_event),
        )
        .await;
        let audit_error: Option<String> = match audited {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(_) => Some(format!(
                "timed out after {:?}",
                crate::proxy::COMPLETION_AUDIT_TIMEOUT
            )),
        };
        if let Some(error) = audit_error {
            tracing::warn!(grant_id = %audit_grant_id, error = %error, "release-completed audit insert failed");
        }
    });

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(response_body),
    )
        .into_response())
}
