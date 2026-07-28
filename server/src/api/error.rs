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
    /// 400 — a bound from addendum #18 was exceeded.
    RequestTooLarge(&'static str),
    /// 400 — proxy path failed canonicalization.
    InvalidPath(&'static str),
    /// 400 — read on a brokered grant, or proxy on a releasing grant.
    WrongMechanism,
    /// 409 — idempotency key reused with a different payload MAC.
    IdempotencyKeyReuse,
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

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        if let ApiFailure::Internal(err) = &self {
            // Log server-side only; the response body stays generic.
            tracing::error!(error = %err, "internal API error");
        }
        let (status, code, message) = self.status_code_message();
        (status, Json(ApiError::new(code, message))).into_response()
    }
}

impl From<anyhow::Error> for ApiFailure {
    fn from(e: anyhow::Error) -> ApiFailure {
        ApiFailure::Internal(e)
    }
}
