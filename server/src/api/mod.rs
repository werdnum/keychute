//! Client-facing REST API (`/v1/…`). Contract: docs/IMPLEMENTATION.md
//! §"HTTP API" plus the pinned review addendum.

pub mod canonical;
pub mod error;
pub mod grants;
pub mod requests;

use crate::authn::client::AuthedClient;
use crate::db;
use crate::state::AppState;
use axum::routing::{any, get, post};
use axum::Router;
use error::ApiFailure;
use keychute_types::{AccessRequestStatus, Mechanism, RequestState, Tier};
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/access-requests", post(requests::create))
        .route("/v1/access-requests/{id}", get(requests::status))
        .route("/v1/access-requests/{id}/wait", get(requests::wait))
        .route("/v1/grants/{id}/read", post(grants::read))
        .route("/v1/grants/{id}/proxy", any(crate::proxy::proxy_root))
        .route(
            "/v1/grants/{id}/proxy/{*path}",
            any(crate::proxy::proxy_path),
        )
        .with_state(state)
}

/// Build the public status shape for a request row (grant id resolved for
/// approved requests).
pub(crate) async fn status_from_row(
    state: &AppState,
    row: &db::AccessRequestRow,
) -> Result<AccessRequestStatus, ApiFailure> {
    let request_state = RequestState::from_str_opt(&row.state)
        .ok_or_else(|| ApiFailure::Internal(anyhow::anyhow!("unknown request state")))?;
    let grant_id = if request_state == RequestState::Approved {
        db::api_ext::get_grant_by_request(&state.db, row.id)
            .await?
            .map(|g| g.id)
    } else {
        None
    };
    Ok(AccessRequestStatus {
        request_id: row.id,
        state: request_state,
        grant_id,
        deny_reason: row.deny_reason.clone(),
        expires_at: row.expires_at,
    })
}

/// Fetch a grant enforcing ownership (mismatch → 404, addendum #1).
pub(crate) async fn owned_grant(
    state: &AppState,
    client: &AuthedClient,
    id: Uuid,
) -> Result<db::GrantRow, ApiFailure> {
    let grant = db::get_grant(&state.db, id)
        .await?
        .ok_or(ApiFailure::NotFound)?;
    if grant.client_name != client.name() {
        return Err(ApiFailure::NotFound);
    }
    Ok(grant)
}

/// Access-time revalidation (addendum #15): client exists + enabled,
/// mechanism still allowed, tier within client cap, and — when the secret row
/// exists — secret enabled and tier within its cap. Returns the secret row
/// for the caller's use. Revocation/expiry are enforced atomically by
/// `begin_grant_use`.
pub(crate) async fn revalidate_grant(
    state: &AppState,
    grant: &db::GrantRow,
) -> Result<Option<db::SecretRow>, ApiFailure> {
    let client = db::get_client_by_name(&state.db, &grant.client_name)
        .await?
        .ok_or(ApiFailure::RevalidationFailed)?;
    if !client.enabled {
        return Err(ApiFailure::RevalidationFailed);
    }
    let mechanism =
        Mechanism::from_str_opt(&grant.mechanism).ok_or(ApiFailure::RevalidationFailed)?;
    if !client.mechanisms.iter().any(|m| m == &grant.mechanism) {
        return Err(ApiFailure::RevalidationFailed);
    }
    let tier = mechanism.tier();
    let client_max = Tier::from_int(client.max_tier).ok_or(ApiFailure::RevalidationFailed)?;
    if tier > client_max {
        return Err(ApiFailure::RevalidationFailed);
    }
    let secret = db::get_secret_by_name(&state.db, &grant.secret_name).await?;
    if let Some(s) = &secret {
        if !s.enabled {
            return Err(ApiFailure::RevalidationFailed);
        }
        let secret_max = Tier::from_int(s.max_tier).ok_or(ApiFailure::RevalidationFailed)?;
        if tier > secret_max {
            return Err(ApiFailure::RevalidationFailed);
        }
    }
    Ok(secret)
}
