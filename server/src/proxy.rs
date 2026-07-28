//! Brokered proxy leg (DESIGN §4, addendum #4/#12/#13/#14/#17).
//!
//! The outbound request is built fresh: caller headers are copied minus the
//! pinned strip list, `Host` and the credential header are synthesized, the
//! path is the validated canonical form re-encoded conservatively, and
//! redirects are never followed (3xx passes through to the caller).

use crate::api::error::ApiFailure;
use crate::api::{owned_grant, revalidate_grant};
use crate::audit::{insert_audit, kinds, AuditEvent};
use crate::authn::client::authenticate_client;
use crate::crypto::AadContext;
use crate::db;
use crate::policy::paths;
use crate::state::{AppState, SlotKind};
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CACHE_CONTROL};
use axum::response::Response;
use base64::Engine;
use futures::StreamExt;
use keychute_types::{Constraints, Mechanism, Origin};
use secrecy::ExposeSecret;
use uuid::Uuid;

/// Headers never forwarded from the caller (addendum #4), lowercase.
const STRIP_LIST: &[&str] = &[
    "host",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "forwarded",
    "x-real-ip",
    "x-http-method-override",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    "x-original-method",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "expect",
];

/// Hop-by-hop headers stripped from the upstream response.
const RESPONSE_STRIP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Header names listed in a `Connection` header's value (comma-separated
/// tokens, case-insensitive).
fn connection_named(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Copy caller headers minus the strip list, minus headers named in the
/// caller's `Connection` value, minus any header equal (case-insensitive) to
/// the injection header. Nothing else is recomputed here.
pub(crate) fn build_outbound_headers(
    caller: &HeaderMap,
    injection_header: &HeaderName,
) -> HeaderMap {
    let dynamic = connection_named(caller);
    let mut out = HeaderMap::new();
    for (name, value) in caller.iter() {
        let n = name.as_str(); // HeaderName is already lowercase.
        if STRIP_LIST.contains(&n)
            || n.starts_with("x-forwarded-")
            || dynamic.iter().any(|d| d == n)
            || name == injection_header
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Strip hop-by-hop headers from the upstream response.
pub(crate) fn build_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let dynamic = connection_named(upstream);
    let mut out = HeaderMap::new();
    for (name, value) in upstream.iter() {
        let n = name.as_str();
        if RESPONSE_STRIP.contains(&n) || dynamic.iter().any(|d| d == n) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// How the credential is placed into the outbound request (addendum #17).
pub(crate) enum InjectionSpec<'a> {
    Bearer,
    Header(&'a str),
    BasicPassword { username: &'a str },
}

/// Build the injection header. Fails closed with `bad-credential-encoding`
/// when the secret (or template) cannot form a valid header value; the value
/// is marked sensitive so it is never logged.
pub(crate) fn injection_header(
    spec: &InjectionSpec<'_>,
    secret: &[u8],
) -> Result<(HeaderName, HeaderValue), ApiFailure> {
    fn header_safe(bytes: &[u8]) -> bool {
        !bytes.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0)
    }
    fn value(bytes: Vec<u8>) -> Result<HeaderValue, ApiFailure> {
        let mut v =
            HeaderValue::from_bytes(&bytes).map_err(|_| ApiFailure::BadCredentialEncoding)?;
        v.set_sensitive(true);
        Ok(v)
    }

    match spec {
        InjectionSpec::Bearer => {
            if !header_safe(secret) {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            let mut bytes = b"Bearer ".to_vec();
            bytes.extend_from_slice(secret);
            Ok((AUTHORIZATION, value(bytes)?))
        }
        InjectionSpec::Header(name) => {
            let lower = name.to_ascii_lowercase();
            if STRIP_LIST.contains(&lower.as_str()) || lower.starts_with("x-forwarded-") {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ApiFailure::BadCredentialEncoding)?;
            if !header_safe(secret) {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            Ok((header_name, value(secret.to_vec())?))
        }
        InjectionSpec::BasicPassword { username } => {
            if username.contains(':')
                || username.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            let mut credentials = Vec::with_capacity(username.len() + 1 + secret.len());
            credentials.extend_from_slice(username.as_bytes());
            credentials.push(b':');
            credentials.extend_from_slice(secret);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&credentials);
            let mut bytes = b"Basic ".to_vec();
            bytes.extend_from_slice(encoded.as_bytes());
            Ok((AUTHORIZATION, value(bytes)?))
        }
    }
}

/// ANY /v1/grants/{id}/proxy — root path.
pub async fn proxy_root(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    req: Request,
) -> Result<Response, ApiFailure> {
    handle(state, id, req).await
}

/// ANY /v1/grants/{id}/proxy/{*path}
pub async fn proxy_path(
    State(state): State<AppState>,
    Path((id, _rest)): Path<(Uuid, String)>,
    req: Request,
) -> Result<Response, ApiFailure> {
    handle(state, id, req).await
}

async fn handle(state: AppState, grant_id: Uuid, req: Request) -> Result<Response, ApiFailure> {
    let deadline =
        std::time::Duration::from_secs(state.config.limits.proxy_stream_deadline_seconds);
    match tokio::time::timeout(deadline, handle_inner(&state, grant_id, req, deadline)).await {
        Ok(result) => result,
        Err(_) => Err(ApiFailure::UpstreamTimeout),
    }
}

async fn handle_inner(
    state: &AppState,
    grant_id: Uuid,
    req: Request,
    deadline: std::time::Duration,
) -> Result<Response, ApiFailure> {
    let (parts, body) = req.into_parts();
    let client = authenticate_client(state, &parts.headers).await?;

    let grant = owned_grant(state, &client, grant_id).await?;
    if Mechanism::from_str_opt(&grant.mechanism) != Some(Mechanism::Brokered) {
        return Err(ApiFailure::WrongMechanism);
    }
    let secret = revalidate_grant(state, &grant)
        .await?
        .ok_or(ApiFailure::PayloadLost)?;

    // Slot held for the whole request/response stream lifetime (moved into
    // the response body stream below).
    let slot = state
        .try_take_slot(client.name(), SlotKind::Proxy)
        .ok_or(ApiFailure::TooManyStreams)?;

    let constraints: Constraints = serde_json::from_value(grant.constraints.clone())
        .map_err(|e| ApiFailure::Internal(e.into()))?;

    // Method must be one of the grant's (uppercase compare).
    let method = parts.method.as_str().to_ascii_uppercase();
    if !constraints.methods.is_empty()
        && !constraints
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method))
    {
        return Err(ApiFailure::PolicyDenied(
            "method not allowed by grant".into(),
        ));
    }

    // Path: raw request path minus the route prefix, canonicalized.
    let raw_path = parts.uri.path();
    let prefix = format!("/v1/grants/{grant_id}/proxy");
    let rest = raw_path
        .strip_prefix(&prefix)
        .ok_or_else(|| ApiFailure::Internal(anyhow::anyhow!("route prefix mismatch")))?;
    let rest = if rest.is_empty() { "/" } else { rest };
    let canonical = paths::canonicalize(rest).map_err(ApiFailure::InvalidPath)?;
    if !constraints.path_prefixes.is_empty()
        && !constraints
            .path_prefixes
            .iter()
            .any(|p| paths::prefix_matches(p, &canonical))
    {
        return Err(ApiFailure::PolicyDenied("path not allowed by grant".into()));
    }

    // Single-origin grants in v1.
    let origin: &Origin = match constraints.origins.as_slice() {
        [o] => o,
        _ => {
            return Err(ApiFailure::Internal(anyhow::anyhow!(
                "brokered grant must have exactly one origin"
            )))
        }
    };

    // Resolve the credential version BEFORE use-accounting (pins the audit).
    let version = db::get_secret_version(&state.db, secret.id, secret.current_version)
        .await?
        .ok_or(ApiFailure::PayloadLost)?;

    // The write-ahead attempt row records where the credential is about to be
    // sent (method/origin/path), before anything leaves the process.
    let target = db::AuditTarget {
        method: method.clone(),
        origin: origin.to_display(),
        path: canonical.clone(),
    };
    match db::begin_grant_use(
        &state.db,
        grant_id,
        None,
        Some(version.id),
        kinds::PROXY_ATTEMPT,
        state.config.limits.replay_window_seconds,
        Some(&target),
    )
    .await?
    {
        db::GrantUse::FirstUse { .. } => {}
        db::GrantUse::NotFound => return Err(ApiFailure::NotFound),
        db::GrantUse::ExpiredOrRevoked => return Err(ApiFailure::GrantExpired),
        db::GrantUse::Exhausted => return Err(ApiFailure::GrantExhausted),
        db::GrantUse::Replay { .. } => {
            return Err(ApiFailure::Internal(anyhow::anyhow!(
                "replay outcome without idempotency key"
            )))
        }
    }

    // Decrypt the credential.
    let plaintext = state
        .keyset
        .open(
            &version.ciphertext,
            &version.nonce,
            &version.wrapped_dek,
            &version.kek_id,
            AadContext::SecretVersion {
                secret_id: version.secret_id,
                version: version.version,
            },
        )
        .map_err(|e| ApiFailure::Internal(e.into()))?;

    // Injection header (confined expose_secret site: proxy header injection).
    let basic_username: String;
    let spec = match secret.injection_kind.as_str() {
        "bearer" => InjectionSpec::Bearer,
        "header" => {
            let name = secret
                .injection_header
                .as_deref()
                .ok_or(ApiFailure::BadCredentialEncoding)?;
            InjectionSpec::Header(name)
        }
        "basic" | "basic-password" => {
            // The username lives in `injection_username` (migration 0003); the
            // UI's create path stores it in `injection_header` for `basic`, so
            // fall back to that.
            basic_username = db::api_ext::get_injection_username(&state.db, secret.id)
                .await?
                .or_else(|| secret.injection_header.clone())
                .unwrap_or_default();
            InjectionSpec::BasicPassword {
                username: &basic_username,
            }
        }
        _ => return Err(ApiFailure::BadCredentialEncoding),
    };
    let (header_name, header_value) = injection_header(&spec, plaintext.expose_secret())?;
    let mut outbound = build_outbound_headers(&parts.headers, &header_name);
    outbound.insert(header_name, header_value);
    forward(
        state, parts, body, grant, version.id, origin, &canonical, &method, outbound, slot,
        deadline,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    state: &AppState,
    parts: axum::http::request::Parts,
    body: Body,
    grant: db::GrantRow,
    secret_version_id: Uuid,
    origin: &Origin,
    canonical_path: &str,
    method: &str,
    outbound_headers: HeaderMap,
    slot: crate::state::SlotGuard,
    deadline: std::time::Duration,
) -> Result<Response, ApiFailure> {
    // Outbound URL: parse the approved origin, then set path/query on the
    // parsed URL (addendum #12) — never string-concatenation.
    let mut url = url::Url::parse(&origin.to_display())
        .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("origin parse: {e}")))?;
    url.set_path(&paths::encode_for_forwarding(canonical_path));
    url.set_query(parts.uri.query());

    // Request body, capped.
    let body_bytes = axum::body::to_bytes(body, state.config.limits.proxy_max_body_bytes)
        .await
        .map_err(|_| ApiFailure::BodyTooLarge)?;

    let upstream = state
        .upstream
        .request(parts.method.clone(), url)
        .headers(outbound_headers)
        .body(body_bytes)
        // Covers the whole upstream exchange including body streaming.
        .timeout(deadline)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                ApiFailure::UpstreamTimeout
            } else {
                ApiFailure::UpstreamUnreachable
            }
        })?;

    let status = upstream.status();

    // proxy-completed audit row: method/origin/path/status, never bodies.
    insert_audit(
        &state.db,
        &AuditEvent {
            kind: kinds::PROXY_COMPLETED,
            request_id: Some(grant.request_id),
            grant_id: Some(grant.id),
            client_name: Some(grant.client_name.clone()),
            secret_name: Some(grant.secret_name.clone()),
            secret_version_id: Some(secret_version_id),
            method: Some(method.to_owned()),
            origin: Some(origin.to_display()),
            path: Some(canonical_path.to_owned()),
            status: Some(status.as_u16() as i32),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| ApiFailure::Internal(e.into()))?;

    let mut headers = build_response_headers(upstream.headers());
    // Addendum #14: override upstream's cache policy on every proxied response.
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    // Stream the body back; the slot guard rides along until the stream drops.
    let stream = upstream.bytes_stream().map(move |chunk| {
        let _slot = &slot;
        chunk.map_err(std::io::Error::other)
    });
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn strip_list_removes_pinned_and_connection_named_headers() {
        let caller = hm(&[
            ("Host", "evil.example.com"),
            ("Authorization", "Bearer caller-token"),
            ("Proxy-Authorization", "x"),
            ("Cookie", "session=1"),
            ("Set-Cookie", "a=b"),
            ("Forwarded", "for=1.2.3.4"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Forwarded-Host", "evil"),
            ("X-Real-IP", "1.2.3.4"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Method-Override", "DELETE"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Original-Method", "DELETE"),
            ("Connection", "x-foo, keep-alive"),
            ("Keep-Alive", "timeout=5"),
            ("TE", "trailers"),
            ("Trailer", "Expires"),
            ("Transfer-Encoding", "chunked"),
            ("Upgrade", "websocket"),
            ("Content-Length", "42"),
            ("Expect", "100-continue"),
            ("X-Foo", "connection-named, must go"),
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
            ("User-Agent", "test-client"),
            ("X-Api-Key", "should-be-stripped-as-injection"),
        ]);
        let injection = HeaderName::from_static("x-api-key");
        let out = build_outbound_headers(&caller, &injection);

        let kept: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        assert_eq!(out.len(), 3, "kept: {kept:?}");
        assert_eq!(out.get("accept").unwrap(), "application/json");
        assert_eq!(out.get("content-type").unwrap(), "application/json");
        assert_eq!(out.get("user-agent").unwrap(), "test-client");
    }

    #[test]
    fn response_strip_removes_hop_by_hop() {
        let upstream = hm(&[
            ("Connection", "x-upstream-internal"),
            ("Keep-Alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("Upgrade", "h2c"),
            ("TE", "trailers"),
            ("Trailer", "X-Checksum"),
            ("Proxy-Connection", "keep-alive"),
            ("X-Upstream-Internal", "secret-routing"),
            ("Set-Cookie", "upstream=state"),
            ("Content-Type", "text/plain"),
            ("Cache-Control", "public, max-age=3600"),
        ]);
        let out = build_response_headers(&upstream);
        assert!(out.get("connection").is_none());
        assert!(out.get("keep-alive").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert!(out.get("upgrade").is_none());
        assert!(out.get("te").is_none());
        assert!(out.get("trailer").is_none());
        assert!(out.get("proxy-connection").is_none());
        // Named in upstream Connection value.
        assert!(out.get("x-upstream-internal").is_none());
        // Upstream Set-Cookie passes through (upstream state for the client).
        assert_eq!(out.get("set-cookie").unwrap(), "upstream=state");
        assert_eq!(out.get("content-type").unwrap(), "text/plain");
        // The handler later overrides cache-control; passthrough here is fine.
        assert_eq!(out.get("cache-control").unwrap(), "public, max-age=3600");
    }

    #[test]
    fn bearer_injection() {
        let (name, value) = injection_header(&InjectionSpec::Bearer, b"tok-123").unwrap();
        assert_eq!(name, AUTHORIZATION);
        assert!(value.is_sensitive());
        assert_eq!(value.as_bytes(), b"Bearer tok-123");
    }

    #[test]
    fn named_header_injection() {
        let (name, value) =
            injection_header(&InjectionSpec::Header("X-Api-Key"), b"secret-v").unwrap();
        assert_eq!(name.as_str(), "x-api-key");
        assert!(value.is_sensitive());
        assert_eq!(value.as_bytes(), b"secret-v");
    }

    #[test]
    fn named_header_rejects_reserved_names() {
        for reserved in ["Host", "Authorization", "Connection", "X-Forwarded-For"] {
            assert!(matches!(
                injection_header(&InjectionSpec::Header(reserved), b"v"),
                Err(ApiFailure::BadCredentialEncoding)
            ));
        }
        assert!(matches!(
            injection_header(&InjectionSpec::Header("bad name!"), b"v"),
            Err(ApiFailure::BadCredentialEncoding)
        ));
    }

    #[test]
    fn basic_password_injection() {
        let (name, value) =
            injection_header(&InjectionSpec::BasicPassword { username: "svc" }, b"p4ss").unwrap();
        assert_eq!(name, AUTHORIZATION);
        assert!(value.is_sensitive());
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(b"svc:p4ss")
        );
        assert_eq!(value.as_bytes(), expected.as_bytes());
        // Binary secret bytes are fine for basic (base64-armored).
        assert!(injection_header(
            &InjectionSpec::BasicPassword { username: "svc" },
            &[0xff, 0x00, 0x0d, 0x0a],
        )
        .is_ok());
        // Colon in the username is ambiguous — fail closed.
        assert!(matches!(
            injection_header(&InjectionSpec::BasicPassword { username: "a:b" }, b"p"),
            Err(ApiFailure::BadCredentialEncoding)
        ));
    }

    #[test]
    fn bad_bytes_fail_closed() {
        for bad in [&b"with\rcr"[..], b"with\nlf", b"with\0nul"] {
            assert!(matches!(
                injection_header(&InjectionSpec::Bearer, bad),
                Err(ApiFailure::BadCredentialEncoding)
            ));
            assert!(matches!(
                injection_header(&InjectionSpec::Header("X-Api-Key"), bad),
                Err(ApiFailure::BadCredentialEncoding)
            ));
        }
    }
}
