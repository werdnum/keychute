//! API error type: maps failures onto the JSON problem shape
//! `{"error": {"code": "...", "message": "..."}}`.
//!
//! Messages must never embed secret material or client-supplied context.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use keychute_types::ApiError;

/// Every way a client-facing handler can fail. `IntoResponse` produces the
/// standard error envelope with the proper status code.
#[derive(Debug)]
pub enum ApiFailure {
    /// 401 — missing/unknown/disabled credential. Deliberately uniform.
    Unauthenticated,
    /// 404 — absent OR owned by a different client (do not confirm existence).
    NotFound,
    /// 400 — malformed or semantically invalid request.
    InvalidRequest(&'static str),
    /// 405 — the route exists but not for this method. Axum's own method
    /// rejection carries no marker, so the router hands it here instead.
    MethodNotAllowed,
    /// 400 — a bound from addendum #18 was exceeded.
    RequestTooLarge(&'static str),
    /// 400 — proxy path failed canonicalization.
    InvalidPath(&'static str),
    /// 400 — read on a brokered grant, or proxy on a releasing grant.
    WrongMechanism,
    /// 409 — idempotency key reused with a different payload MAC.
    IdempotencyKeyReuse,
    /// 409 — deposit (`POST /v1/secrets`) named a secret that already exists.
    /// The endpoint is create-only: replacing stored credential bytes is an
    /// operator action, never a client one.
    SecretExists,
    /// 403 — policy denied the request (server-vocabulary reason only).
    PolicyDenied(String),
    /// 403 — access-time revalidation failed (addendum #15).
    RevalidationFailed,
    /// 429 — per-client pending-request cap.
    TooManyPending,
    /// 429 — per-client concurrent wait cap.
    TooManyWaits,
    /// 429 — per-client concurrent proxy-stream cap.
    TooManyStreams,
    /// 429 — per-client hourly secret-deposit cap.
    TooManyDeposits,
    /// 410 — grant has no uses left.
    GrantExhausted,
    /// 410 — grant revoked or past `not_after`.
    GrantExpired,
    /// 410 — passthrough payload lost (process restart or purge).
    PayloadLost,
    /// 413 — proxy request body over the configured limit.
    BodyTooLarge,
    /// 502 — credential bytes cannot be placed in the injection header.
    BadCredentialEncoding,
    /// 502 — upstream connection failed.
    UpstreamUnreachable,
    /// 504 — proxy stream deadline elapsed.
    UpstreamTimeout,
    /// 500 — internal error; details are logged, never returned.
    Internal(anyhow::Error),
}

impl ApiFailure {
    fn status_code_message(&self) -> (StatusCode, &'static str, String) {
        match self {
            ApiFailure::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "authentication required".into(),
            ),
            ApiFailure::NotFound => (StatusCode::NOT_FOUND, "not-found", "not found".into()),
            ApiFailure::InvalidRequest(m) => {
                (StatusCode::BAD_REQUEST, "invalid-request", (*m).into())
            }
            ApiFailure::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method-not-allowed",
                "method not allowed on this route".into(),
            ),
            ApiFailure::RequestTooLarge(m) => {
                (StatusCode::BAD_REQUEST, "request-too-large", (*m).into())
            }
            ApiFailure::InvalidPath(m) => (StatusCode::BAD_REQUEST, "invalid-path", (*m).into()),
            ApiFailure::WrongMechanism => (
                StatusCode::BAD_REQUEST,
                "wrong-mechanism",
                "grant mechanism does not support this endpoint".into(),
            ),
            ApiFailure::IdempotencyKeyReuse => (
                StatusCode::CONFLICT,
                "idempotency-key-reuse",
                "idempotency key was already used with a different payload".into(),
            ),
            ApiFailure::SecretExists => (
                StatusCode::CONFLICT,
                "secret-exists",
                "a secret with this name already exists; rotation is operator-only".into(),
            ),
            ApiFailure::PolicyDenied(reason) => {
                (StatusCode::FORBIDDEN, "policy-denied", reason.clone())
            }
            ApiFailure::RevalidationFailed => (
                StatusCode::FORBIDDEN,
                "revalidation-failed",
                "grant is no longer usable".into(),
            ),
            ApiFailure::TooManyPending => (
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-pending",
                "per-client pending request cap reached".into(),
            ),
            ApiFailure::TooManyWaits => (
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-waits",
                "per-client concurrent wait cap reached".into(),
            ),
            ApiFailure::TooManyStreams => (
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-streams",
                "per-client concurrent proxy stream cap reached".into(),
            ),
            ApiFailure::TooManyDeposits => (
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-deposits",
                "per-client secret deposit rate cap reached".into(),
            ),
            ApiFailure::GrantExhausted => (
                StatusCode::GONE,
                "grant-exhausted",
                "grant has no uses remaining".into(),
            ),
            ApiFailure::GrantExpired => (
                StatusCode::GONE,
                "grant-expired",
                "grant is revoked or expired".into(),
            ),
            ApiFailure::PayloadLost => (
                StatusCode::GONE,
                "payload-lost",
                "the grant payload is no longer available; submit a new access request".into(),
            ),
            ApiFailure::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "body-too-large",
                "request body exceeds the proxy limit".into(),
            ),
            ApiFailure::BadCredentialEncoding => (
                StatusCode::BAD_GATEWAY,
                "bad-credential-encoding",
                "credential cannot be encoded for header injection".into(),
            ),
            ApiFailure::UpstreamUnreachable => (
                StatusCode::BAD_GATEWAY,
                "upstream-unreachable",
                "upstream request failed".into(),
            ),
            ApiFailure::UpstreamTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream-timeout",
                "proxy stream deadline elapsed".into(),
            ),
            ApiFailure::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error".into(),
            ),
        }
    }
}

/// Marks a response as KEYCHUTE's own, not a proxied upstream's.
///
/// On the brokered proxy path the two are otherwise indistinguishable: a
/// Keychute `403 policy-denied` and an upstream's own `403` arrive with the
/// same status and both may carry an `{"error": {...}}` body. A client that
/// cannot tell them apart either treats an upstream refusal as a policy denial
/// (and stops asking a human who never said no) or the reverse. Only the
/// server-vocabulary error code goes in the header — the same string already
/// in the body — never client context or credential material.
///
/// `proxy.rs` strips this header from every upstream response, so an upstream
/// cannot forge one.
pub const KEYCHUTE_ERROR_HEADER: &str = "x-keychute-error";

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        if let ApiFailure::Internal(err) = &self {
            // Log server-side only; the response body stays generic.
            tracing::error!(error = %err, "internal API error");
        }
        let (status, code, message) = self.status_code_message();
        let mut resp = (status, Json(ApiError::new(code, message))).into_response();
        // `code` is a fixed server-vocabulary token, so this can never fail to
        // encode; skip the header rather than panic if that ever changes.
        if let Ok(value) = axum::http::HeaderValue::from_str(code) {
            resp.headers_mut().insert(KEYCHUTE_ERROR_HEADER, value);
        }
        resp
    }
}

impl From<anyhow::Error> for ApiFailure {
    fn from(e: anyhow::Error) -> ApiFailure {
        ApiFailure::Internal(e)
    }
}
