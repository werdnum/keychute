//! Client-facing REST API (`/v1/…`). Contract: docs/IMPLEMENTATION.md
//! §"HTTP API" plus the pinned review addendum.

pub mod canonical;
pub mod error;
pub mod grants;
pub mod requests;
pub mod secrets;

use crate::authn::client::AuthedClient;
use crate::db;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use error::ApiFailure;
use keychute_types::{AccessRequestStatus, Mechanism, RequestState, Tier};
use uuid::Uuid;

/// Upper bound on the readiness database probe. Must stay comfortably below a
/// sensible probe `timeoutSeconds` so the endpoint answers rather than hangs.
const READINESS_DB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// `GET /readyz` — readiness. Unlike `/healthz` (process liveness only) this
/// verifies the dependency without which every meaningful operation fails: the
/// database. A pod whose Postgres is unreachable must leave the Service
/// endpoints instead of accepting requests it cannot serve.
///
/// The check is bounded (`SELECT 1` under a short timeout) so a hung
/// connection reports not-ready instead of stalling the probe until kubelet's
/// own timeout. The body is a fixed generic string — connection strings and
/// driver errors (which can carry credentials) are logged, never returned.
async fn readyz(State(state): State<AppState>) -> Response {
    let probe = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db);
    let unready = |detail: String| {
        tracing::warn!(target: "keychute::readiness", %detail, "readiness probe failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            "database unavailable\n",
        )
            .into_response()
    };
    match tokio::time::timeout(READINESS_DB_TIMEOUT, probe).await {
        Ok(Ok(_)) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            "ready\n",
        )
            .into_response(),
        Ok(Err(e)) => unready(e.to_string()),
        Err(_) => unready(format!(
            "database probe timed out after {}s",
            READINESS_DB_TIMEOUT.as_secs()
        )),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // Liveness only: the process is up and the runtime is scheduling.
        // Dependency health belongs on /readyz.
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/v1/access-requests", post(requests::create))
        .route("/v1/access-requests/{id}", get(requests::status))
        .route("/v1/access-requests/{id}/wait", get(requests::wait))
        .route("/v1/secrets", post(secrets::store))
        .route("/v1/grants/{id}", get(grants::info))
        .route("/v1/grants/{id}/read", post(grants::read))
        .route("/v1/grants/{id}/proxy", any(crate::proxy::proxy_root))
        .route(
            "/v1/grants/{id}/proxy/{*path}",
            any(crate::proxy::proxy_path),
        )
        // The last two ways axum answers before a handler runs, and the last
        // two unmarked errors on the API surface: a path under /v1 that
        // matches no route, and a method no route accepts. Both are Keychute's
        // own refusals — the marker is what stops a client attributing them to
        // an upstream, and on these there is no upstream at all.
        //
        // Scoped to /v1 by an explicit catch-all route rather than a router
        // fallback: the UI is merged into this router and its 404 belongs to a
        // human reading HTML, not to the API's error envelope. The proxy's own
        // relayed upstream responses are untouched by either — they come back
        // through a handler, which is exactly why this is done here and not as
        // a blanket response middleware that could not tell the two apart.
        .route("/v1/{*rest}", any(|| async { ApiFailure::NotFound }))
        .method_not_allowed_fallback(|| async { ApiFailure::MethodNotAllowed })
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

/// The id from a `/v1/...{id}...` path, parsed INSIDE the handler.
///
/// A `Path<Uuid>` extractor rejects a malformed id before any handler runs, and
/// axum's own rejection is a bare 400 with no [`error::KEYCHUTE_ERROR_HEADER`]
/// on it. That breaks the contract every other error response here keeps — the
/// marker is how a client tells a Keychute answer from an upstream's, and on
/// these routes an unmarked 400 is Keychute's own. `proxy.rs` already parses
/// the id in the handler for exactly this reason; these routes now do too.
///
/// `NotFound`, not a parse error: a malformed id is certainly not a resource
/// this client owns, and the answer must not distinguish "malformed" from
/// "someone else's" any more than the ownership check does.
pub(crate) fn path_id(raw: &str) -> Result<Uuid, ApiFailure> {
    raw.parse::<Uuid>().map_err(|_| ApiFailure::NotFound)
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
