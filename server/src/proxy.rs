//! Brokered proxy leg (DESIGN §4, addendum #4/#12/#13/#14/#17).
//!
//! The outbound request is built fresh: caller headers are copied minus the
//! pinned strip list, `Host` and the credential header are synthesized, the
//! path is the validated canonical form handed to `Url::set_path` (see
//! [`outbound_url`]), and redirects are never followed (3xx passes through to
//! the caller).

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

/// Hop-by-hop headers stripped from the upstream response — the full RFC set,
/// including the two `Proxy-*` ones the request side also strips. An upstream
/// 407 challenges *its* own proxy hop, not our caller, so `Proxy-Authenticate`
/// must not be forwarded either.
const RESPONSE_STRIP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
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

impl InjectionSpec<'_> {
    /// The half of [`injection_header`] that does NOT need the decrypted
    /// secret: resolve the header name the credential will be set on, and
    /// reject a template that could never form a valid header regardless of
    /// what the secret turns out to be.
    ///
    /// Split out so `handle_inner` can run it BEFORE use-accounting — a
    /// credential whose *template* is unusable can never reach upstream, so it
    /// must not burn a use of a finite-`max_uses` grant (same reasoning as the
    /// 413 body cap). `injection_header` calls it again rather than trusting
    /// the caller to have done so, which keeps it the single definition of
    /// "usable template" for both call sites.
    pub(crate) fn validate(&self) -> Result<HeaderName, ApiFailure> {
        match self {
            InjectionSpec::Bearer => Ok(AUTHORIZATION),
            InjectionSpec::Header(name) => {
                let lower = name.to_ascii_lowercase();
                if STRIP_LIST.contains(&lower.as_str()) || lower.starts_with("x-forwarded-") {
                    return Err(ApiFailure::BadCredentialEncoding);
                }
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ApiFailure::BadCredentialEncoding)
            }
            InjectionSpec::BasicPassword { username } => {
                // `:` would move the field boundary inside the base64 payload,
                // so upstream would see a different username than the operator
                // configured; CR/LF/NUL would make the built header value
                // invalid (or split it).
                if username.contains(':')
                    || username.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                {
                    return Err(ApiFailure::BadCredentialEncoding);
                }
                Ok(AUTHORIZATION)
            }
        }
    }
}

/// Build the injection header. Fails closed with `bad-credential-encoding`
/// when the secret (or template) cannot form a valid header value; the value
/// is marked sensitive so it is never logged.
///
/// Residual, deliberately not moved before use-accounting: the checks below
/// that inspect `secret` (CR/LF/NUL in the plaintext, and `HeaderValue`
/// rejecting the assembled bytes) fail a request AFTER a use has been
/// accounted and a `proxy-attempt` row written, returning 502. Hoisting them
/// would mean decrypting before accounting, which is the worse trade: the
/// plaintext must not enter the process before the use that pays for it is
/// recorded. The template half is hoisted instead (see
/// [`InjectionSpec::validate`]), which covers every failure that does not
/// depend on the stored bytes.
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

    let name = spec.validate()?;
    match spec {
        InjectionSpec::Bearer => {
            if !header_safe(secret) {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            let mut bytes = b"Bearer ".to_vec();
            bytes.extend_from_slice(secret);
            Ok((name, value(bytes)?))
        }
        InjectionSpec::Header(_) => {
            if !header_safe(secret) {
                return Err(ApiFailure::BadCredentialEncoding);
            }
            Ok((name, value(secret.to_vec())?))
        }
        InjectionSpec::BasicPassword { username } => {
            let mut credentials = Vec::with_capacity(username.len() + 1 + secret.len());
            credentials.extend_from_slice(username.as_bytes());
            credentials.push(b':');
            credentials.extend_from_slice(secret);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&credentials);
            let mut bytes = b"Basic ".to_vec();
            bytes.extend_from_slice(encoded.as_bytes());
            Ok((name, value(bytes)?))
        }
    }
}

/// Build the outbound URL from the approved origin and the **canonical**
/// (percent-decoded) path (addendum #12) — parsed URL mutation, never string
/// concatenation.
///
/// `Url::set_path` percent-encodes its argument itself, so the canonical path
/// is handed over decoded. Pre-encoding it first (as an earlier revision did
/// with `paths::encode_for_forwarding`) double-encodes: `/a%20b` canonicalizes
/// to `/a b`, re-encodes to `/a%20b`, and `set_path` would then emit
/// `/a%2520b` — a *different* upstream resource than the one the grant
/// authorized and the audit row recorded.
///
/// Why handing `set_path` a decoded path is safe: `paths::canonicalize` has
/// already rejected every input whose decoded form could change the path's
/// STRUCTURE — encoded `/` (`%2F`) and `\` (`%5C`), raw `\`, `.`/`..`
/// segments, `//`, control characters, and non-UTF-8. So every `/` in the
/// canonical string is a separator the caller genuinely sent, and no segment
/// can be a dot segment; `set_path` cannot smuggle in structure that
/// `prefix_matches` did not see.
///
/// Characters that delimit *other* URL components are handled by `set_path`
/// itself: a decoded `?` or `#` (from `%3F`/`%23`) is percent-encoded into the
/// path, not treated as the start of a query or fragment (asserted in the unit
/// tests). The query is set separately and verbatim from the caller's URI.
///
/// The one character `set_path` does NOT encode is `%` itself (the WHATWG path
/// percent-encode set omits it, so existing escapes survive re-parsing). A
/// canonical path may legitimately contain a literal `%` — raw `/100%25`
/// canonicalizes to `/100%`. Emitting that bare would hand upstream either a
/// malformed escape or, worse, a *second* decode: canonical `/a%41` (from raw
/// `/a%2541`, which is what the operator approved and what the audit log says)
/// would arrive as `/a%41` and be read upstream as `/aA`. So `%` — and only
/// `%` — is escaped here before `set_path` does the rest, which keeps the
/// outbound path exactly single-encoded.
fn outbound_url(
    origin: &str,
    canonical_path: &str,
    query: Option<&str>,
) -> Result<url::Url, url::ParseError> {
    let mut url = url::Url::parse(origin)?;
    url.set_path(&canonical_path.replace('%', "%25"));
    url.set_query(query);
    Ok(url)
}

/// The method actually sent upstream: the normalized (uppercase) form that
/// the grant check authorized and the audit rows record. HTTP methods are
/// case-sensitive on the wire, so forwarding the caller's original casing
/// (e.g. `delete` under a grant permitting `DELETE`) could reach a different
/// upstream operation than the one approved.
fn outbound_method(normalized: &str) -> Result<axum::http::Method, ApiFailure> {
    axum::http::Method::from_bytes(normalized.as_bytes())
        .map_err(|_| ApiFailure::InvalidRequest("invalid HTTP method"))
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

/// The proxied suffix of the raw request path — everything the routes
/// `/v1/grants/{id}/proxy` and `/v1/grants/{id}/proxy/{*path}` leave after the
/// literal `proxy` segment, normalized to `"/"` for the root route.
///
/// Two properties matter here:
///
/// * The grant-id segment is consumed verbatim from the URI, never re-rendered
///   from the parsed `Uuid`. axum accepts non-canonical but valid spellings
///   (uppercase, unhyphenated); formatting the parsed value back out would
///   produce a prefix that no longer matches the raw path, turning an owned,
///   valid grant into a 500.
/// * The returned suffix is still the RAW, un-decoded path. axum's own `{*path}`
///   capture (and `RawPathParams`) percent-decodes captures, which would launder
///   `%2F` and `%2e%2e` past `policy::paths::canonicalize`. Those must keep
///   reaching the canonicalizer in encoded form so they are rejected.
fn proxy_suffix(raw_path: &str) -> Option<&str> {
    // "/v1/grants/" <id> "/" "proxy" <suffix>
    let after_prefix = raw_path.strip_prefix("/v1/grants/")?;
    let (_id, rest) = after_prefix.split_once('/')?;
    let suffix = rest.strip_prefix("proxy")?;
    match suffix.as_bytes().first() {
        None => Some("/"),
        Some(b'/') => Some(suffix),
        // Not the proxy route at all (e.g. `/proxyfoo`); the router would not
        // have dispatched here.
        Some(_) => None,
    }
}

/// Cap on the post-upstream completion-audit insert. That work is deliberately
/// outside the stream deadline (see [`handle`]), but it still needs a bound of
/// its own so a wedged database cannot hold the caller's response open.
pub(crate) const COMPLETION_AUDIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn handle(state: AppState, grant_id: Uuid, req: Request) -> Result<Response, ApiFailure> {
    // ONE deadline covers the whole proxied lifetime: request handling, the
    // upstream exchange, and streaming the response body back to the caller.
    // `forward` sets the reqwest timeout to the time REMAINING at send, which
    // reqwest applies through the end of response-body streaming — so the body
    // stream (which outlives this function) cannot extend the total past the
    // limit; the race below covers everything before that point.
    //
    // The race is DISARMED the moment the upstream exchange produces a
    // response. Past that point the side effect has committed, and the only
    // work left in this function is the completion-audit insert (bounded by
    // `COMPLETION_AUDIT_TIMEOUT`) plus building the response: cancelling it
    // would turn a committed upstream 200 into a 504 and invite the caller to
    // repeat the side effect.
    let limit = std::time::Duration::from_secs(state.config.limits.proxy_stream_deadline_seconds);
    let deadline = tokio::time::Instant::now() + limit;
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    run_before_deadline(
        handle_inner(&state, grant_id, req, deadline, committed_tx),
        committed_rx,
        deadline,
    )
    .await
}

/// Run `inner` under `deadline` until `committed` fires, then let it finish
/// untimed. A `committed` sender dropped WITHOUT a send (an early return, or an
/// upstream exchange that never produced a response) leaves the deadline armed.
async fn run_before_deadline<F>(
    inner: F,
    committed: tokio::sync::oneshot::Receiver<()>,
    deadline: tokio::time::Instant,
) -> Result<Response, ApiFailure>
where
    F: std::future::Future<Output = Result<Response, ApiFailure>>,
{
    let disarm = async move {
        if committed.await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(inner);
    tokio::select! {
        biased;
        result = &mut inner => result,
        _ = disarm => inner.await,
        _ = tokio::time::sleep_until(deadline) => Err(ApiFailure::UpstreamTimeout),
    }
}

async fn handle_inner(
    state: &AppState,
    grant_id: Uuid,
    req: Request,
    deadline: tokio::time::Instant,
    committed: tokio::sync::oneshot::Sender<()>,
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
    let rest = proxy_suffix(parts.uri.path())
        .ok_or_else(|| ApiFailure::Internal(anyhow::anyhow!("route prefix mismatch")))?;
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

    // Buffer and size-check the request body BEFORE use-accounting: a 413 must
    // not burn a use of a finite-max_uses grant (it never reaches upstream).
    // Read manually rather than via `to_bytes` with a limit so a genuine
    // size-cap hit (413) is distinguishable from other read failures (400).
    let max_body = state.config.limits.proxy_max_body_bytes;
    let mut body_stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.map_err(|_| ApiFailure::InvalidRequest("request body read failed"))?;
        if buf.len().saturating_add(chunk.len()) > max_body {
            return Err(ApiFailure::BodyTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    let body_bytes = axum::body::Bytes::from(buf);

    // Resolve the credential version BEFORE use-accounting (pins the audit).
    let version = db::get_secret_version(&state.db, secret.id, secret.current_version)
        .await?
        .ok_or(ApiFailure::PayloadLost)?;

    // How the credential will be placed into the outbound request — resolved
    // BEFORE use-accounting for the same reason as the 413 above: every failure
    // here is `bad-credential-encoding` for a credential that can never reach
    // upstream, and an unusable credential must not burn a use of a
    // finite-max_uses grant. Nothing here needs the plaintext, so the decrypt
    // still happens only once a use has been accounted.
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
            // fall back to that. A row with neither fails CLOSED (like the
            // `header` kind above): defaulting to "" would ship
            // `Basic base64(":" + secret)` upstream, leaking the secret into
            // the upstream's auth-failure log.
            basic_username = db::api_ext::get_injection_username(&state.db, secret.id)
                .await?
                .or_else(|| secret.injection_header.clone())
                .ok_or(ApiFailure::BadCredentialEncoding)?;
            InjectionSpec::BasicPassword {
                username: &basic_username,
            }
        }
        _ => return Err(ApiFailure::BadCredentialEncoding),
    };
    // Everything about the template that can fail without seeing the plaintext
    // (bad/stripped header name, a basic username carrying `:` or CR/LF/NUL) is
    // decided here, still before use-accounting. `injection_header` re-runs it
    // once the secret is in hand; see its docs for the residual that genuinely
    // cannot move.
    spec.validate()?;

    // The write-ahead attempt row records where the credential is about to be
    // sent (method/origin/path), before anything leaves the process. The
    // caller's query string is forwarded verbatim, so it is part of "where":
    // it is recorded alongside the path — otherwise `?limit=10` and
    // `?transfer_to=attacker` would produce identical audit rows.
    let audited_path = match parts.uri.query() {
        Some(q) => format!("{canonical}?{q}"),
        None => canonical.clone(),
    };
    let target = db::AuditTarget {
        method: method.clone(),
        origin: origin.to_display(),
        path: audited_path.clone(),
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
    let (header_name, header_value) = injection_header(&spec, plaintext.expose_secret())?;
    let mut outbound = build_outbound_headers(&parts.headers, &header_name);
    outbound.insert(header_name, header_value);
    forward(
        state,
        parts,
        body_bytes,
        grant,
        version.id,
        origin,
        &canonical,
        &audited_path,
        &method,
        outbound,
        slot,
        deadline,
        committed,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    state: &AppState,
    parts: axum::http::request::Parts,
    // Already buffered and size-checked by the caller (before use-accounting).
    body_bytes: axum::body::Bytes,
    grant: db::GrantRow,
    secret_version_id: Uuid,
    origin: &Origin,
    canonical_path: &str,
    // `canonical_path` plus the caller's verbatim query string, for audit.
    audited_path: &str,
    method: &str,
    outbound_headers: HeaderMap,
    slot: crate::state::SlotGuard,
    deadline: tokio::time::Instant,
    // Fired once upstream has responded, to disarm the outer deadline race.
    committed: tokio::sync::oneshot::Sender<()>,
) -> Result<Response, ApiFailure> {
    let url = outbound_url(&origin.to_display(), canonical_path, parts.uri.query())
        .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("origin parse: {e}")))?;

    let upstream = state
        .upstream
        // The NORMALIZED method — the one the grant check authorized and the
        // audit rows record — never the caller's original casing.
        .request(outbound_method(method)?, url)
        .headers(outbound_headers)
        .body(body_bytes)
        // Covers the rest of the upstream exchange including response-body
        // streaming: the remaining share of the single stream deadline.
        .timeout(deadline.saturating_duration_since(tokio::time::Instant::now()))
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

    // Upstream has responded, so whatever side effect it had has committed:
    // release the caller's response from the stream deadline (see `handle`).
    // Nothing below may turn that committed response into an error status.
    let _ = committed.send(());

    // proxy-completed audit row: method/origin/path/status, never bodies.
    // Neither a failing nor a slow insert may become a 500 or a 504 here: the
    // caller would retry and duplicate the side effect (or find a finite-use
    // grant already burned). The design allows an attempt row without a
    // completion row after a mid-release failure; log loudly either way and
    // return the upstream response.
    let audited = tokio::time::timeout(
        COMPLETION_AUDIT_TIMEOUT,
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
                path: Some(audited_path.to_owned()),
                status: Some(status.as_u16() as i32),
                ..Default::default()
            },
        ),
    )
    .await;
    let audit_error: Option<String> = match audited {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some(format!("timed out after {COMPLETION_AUDIT_TIMEOUT:?}")),
    };
    if let Some(error) = audit_error {
        tracing::error!(
            error = %error,
            grant_id = %grant.id,
            client_name = %grant.client_name,
            "proxy-completed audit insert failed; returning upstream response \
             (attempt row exists, completion row is missing)"
        );
    }

    let mut headers = build_response_headers(upstream.headers());
    // Addendum #14: override upstream's cache policy on every proxied response.
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    // Stream the body back; the slot guard rides along until the stream drops.
    // The response body is capped at the same limit as the request body
    // (values.yaml documents `proxyMaxBodyBytes` as covering both); crossing
    // it errors the stream, which terminates the caller's connection.
    let max_body = state.config.limits.proxy_max_body_bytes;
    let mut total: usize = 0;
    let stream = upstream.bytes_stream().map(move |chunk| {
        let _slot = &slot;
        let bytes = chunk.map_err(std::io::Error::other)?;
        total = total.saturating_add(bytes.len());
        if total > max_body {
            return Err(std::io::Error::other(
                "upstream response body exceeds the proxy limit",
            ));
        }
        Ok(bytes)
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
            ("Proxy-Authenticate", "Basic realm=\"upstream-proxy\""),
            ("Proxy-Authorization", "Basic dXA6cHc="),
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
        // A 407 challenge addresses the upstream's own proxy hop, not our
        // caller: it must not be forwarded.
        assert!(out.get("proxy-authenticate").is_none());
        assert!(out.get("proxy-authorization").is_none());
        // Named in upstream Connection value.
        assert!(out.get("x-upstream-internal").is_none());
        // Upstream Set-Cookie passes through (upstream state for the client).
        assert_eq!(out.get("set-cookie").unwrap(), "upstream=state");
        assert_eq!(out.get("content-type").unwrap(), "text/plain");
        // The handler later overrides cache-control; passthrough here is fine.
        assert_eq!(out.get("cache-control").unwrap(), "public, max-age=3600");
    }

    /// The RFC hop-by-hop set, which the response filter must cover whole
    /// (DESIGN §4 / IMPLEMENTATION #4: "strips hop-by-hop headers likewise").
    #[test]
    fn response_strip_covers_the_whole_hop_by_hop_set() {
        for h in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(RESPONSE_STRIP.contains(&h), "response strip missing {h}");
        }
    }

    /// Once the upstream exchange has produced a response, the stream deadline
    /// no longer applies: post-upstream work (the completion-audit insert) must
    /// not be able to turn a committed upstream response into a 504.
    #[tokio::test]
    async fn deadline_is_disarmed_once_upstream_has_responded() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let inner = async move {
            let _ = tx.send(());
            // Stands in for a slow completion-audit insert.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            Ok(Response::new(Body::empty()))
        };
        let out = run_before_deadline(inner, rx, deadline).await;
        assert!(out.is_ok(), "committed response must survive the deadline");
    }

    /// Without that signal — an early return, or an upstream exchange that
    /// never produced a response — the deadline still bites.
    #[tokio::test]
    async fn deadline_still_applies_before_upstream_responds() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let inner = async move {
            // Sender dropped without a send, as an early `?` return would.
            drop(tx);
            std::future::pending::<Result<Response, ApiFailure>>().await
        };
        assert!(matches!(
            run_before_deadline(inner, rx, deadline).await,
            Err(ApiFailure::UpstreamTimeout)
        ));
    }

    #[test]
    fn proxy_suffix_is_raw_and_uuid_spelling_agnostic() {
        let canonical = "0f2f0a4e-1c3a-4f5b-8a9d-2b7c6e5d4f30";
        let upper = canonical.to_ascii_uppercase();
        let unhyphenated = canonical.replace('-', "");

        for id in [canonical.to_owned(), upper, unhyphenated] {
            assert_eq!(
                proxy_suffix(&format!("/v1/grants/{id}/proxy")),
                Some("/"),
                "root route for {id}"
            );
            assert_eq!(
                proxy_suffix(&format!("/v1/grants/{id}/proxy/v1/echo")),
                Some("/v1/echo"),
                "sub-path for {id}"
            );
        }

        // The suffix stays percent-encoded so canonicalize() can reject it.
        assert_eq!(
            proxy_suffix(&format!("/v1/grants/{canonical}/proxy/v1/a%2Fb")),
            Some("/v1/a%2Fb")
        );
        assert!(paths::canonicalize("/v1/a%2Fb").is_err());
        assert_eq!(
            proxy_suffix(&format!("/v1/grants/{canonical}/proxy/v1/%2e%2e/secret")),
            Some("/v1/%2e%2e/secret")
        );
        assert!(paths::canonicalize("/v1/%2e%2e/secret").is_err());
        assert_eq!(
            proxy_suffix(&format!("/v1/grants/{canonical}/proxy/v1/../secret")),
            Some("/v1/../secret")
        );
        assert!(paths::canonicalize("/v1/../secret").is_err());

        // Nested `/proxy/` segments in the suffix are not re-split.
        assert_eq!(
            proxy_suffix(&format!("/v1/grants/{canonical}/proxy/proxy/x")),
            Some("/proxy/x")
        );

        // Shapes the router would never dispatch here.
        assert_eq!(proxy_suffix("/v1/grants/abc/proxyfoo"), None);
        assert_eq!(proxy_suffix("/v1/grants/abc"), None);
        assert_eq!(proxy_suffix("/healthz"), None);
    }

    /// Full production path: canonicalize the raw request suffix exactly as
    /// `handle_inner` does, then build the outbound URL from it.
    fn forwarded_path(raw: &str) -> String {
        let canonical = paths::canonicalize(raw).expect("canonicalize");
        let url = outbound_url("https://up.example.com", &canonical, None).unwrap();
        url.path().to_owned()
    }

    #[test]
    fn outbound_path_is_single_encoded() {
        // Nothing to encode: passes through untouched.
        assert_eq!(forwarded_path("/v1/echo"), "/v1/echo");

        // A raw space and its encoded spelling canonicalize to the same path
        // and must forward identically — single-encoded, never `%2520`.
        assert_eq!(forwarded_path("/a b"), "/a%20b");
        assert_eq!(forwarded_path("/a%20b"), "/a%20b");

        // Non-ASCII: UTF-8 percent-encoded once.
        assert_eq!(forwarded_path("/ünïcode"), "/%C3%BCn%C3%AFcode");
        assert_eq!(forwarded_path("/%C3%BCn%C3%AFcode"), "/%C3%BCn%C3%AFcode");

        // Literal percent. `/100%25` canonicalizes to `/100%`; upstream must
        // receive `%25` back so it decodes to the approved, audited path — a
        // bare `%` would be a malformed escape.
        assert_eq!(forwarded_path("/100%25"), "/100%25");
        // And the double-decode trap: raw `%2541` was approved as the literal
        // characters `%41`, so upstream must not be able to read it as `A`.
        assert_eq!(forwarded_path("/a%2541"), "/a%2541");

        // Plus sign is not a space in a path; it survives verbatim.
        assert_eq!(forwarded_path("/a+b"), "/a+b");
    }

    #[test]
    fn decoded_delimiters_stay_inside_the_path() {
        // `%3F`/`%23` decode to `?`/`#`; `set_path` must re-encode them into
        // the path rather than starting a query or fragment.
        let canonical = paths::canonicalize("/a%3Fb%23c").unwrap();
        assert_eq!(canonical, "/a?b#c");
        let url = outbound_url("https://up.example.com", &canonical, None).unwrap();
        assert_eq!(url.path(), "/a%3Fb%23c");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert_eq!(url.as_str(), "https://up.example.com/a%3Fb%23c");

        // The caller's real query is attached separately and verbatim.
        let url = outbound_url("https://up.example.com", &canonical, Some("x=1&y=2")).unwrap();
        assert_eq!(url.path(), "/a%3Fb%23c");
        assert_eq!(url.query(), Some("x=1&y=2"));
    }

    #[test]
    fn canonicalize_rejects_everything_that_would_be_structure() {
        // The safety argument for handing `set_path` a DECODED path: no
        // canonical path can contain a separator or dot segment that
        // `prefix_matches` did not already see.
        for bad in [
            "/a%2Fb",  // encoded '/'
            "/a%2fb",  // lowercase hex
            "/a%5Cb",  // encoded '\'
            "/a\\b",   // raw '\'
            "/a/../b", // dot segment
            "/a/%2e%2e/b",
            "/a/..;b/c",                // dot-dot behind a path parameter
            "/v1/account/..;/v1/admin", // servlet-style prefix escape
            "/a/..%3b/b",               // encoded ';' spelling
            "/a//b",                    // duplicate slash
            "/a%00b",                   // control character
            "/a%FFb",                   // invalid UTF-8
            "/a%2",                     // truncated escape
            "/a%zz",                    // invalid escape
        ] {
            assert!(paths::canonicalize(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn outbound_url_keeps_the_approved_origin() {
        // Origin host/port/scheme are never influenced by the path.
        let url = outbound_url("https://up.example.com:8443", "/v1/echo", None).unwrap();
        assert_eq!(url.as_str(), "https://up.example.com:8443/v1/echo");
    }

    #[test]
    fn outbound_method_is_the_normalized_uppercase_form() {
        // handle_inner uppercases the caller's method before the grant check;
        // forward sends exactly that normalized form upstream, so what is
        // authorized, what is sent, and what is audited all agree even when
        // the caller spells the method in lowercase.
        for raw in ["delete", "Delete", "DELETE"] {
            let normalized = raw.to_ascii_uppercase();
            let m = outbound_method(&normalized).unwrap();
            assert_eq!(m, axum::http::Method::DELETE);
            assert_eq!(m.as_str(), "DELETE");
        }
        // Extension methods survive normalization too.
        let m = outbound_method(&"m-search".to_ascii_uppercase()).unwrap();
        assert_eq!(m.as_str(), "M-SEARCH");
        // Non-token bytes fail rather than being forwarded.
        assert!(matches!(
            outbound_method("GE T"),
            Err(ApiFailure::InvalidRequest(_))
        ));
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

    /// `validate` decides every template failure without the plaintext, so the
    /// proxy can run it before use-accounting. Whatever it rejects,
    /// `injection_header` must reject too — for ANY secret, including one that
    /// would otherwise have produced a perfectly good header.
    #[test]
    fn validate_matches_injection_header_without_the_secret() {
        assert_eq!(InjectionSpec::Bearer.validate().unwrap(), AUTHORIZATION);
        assert_eq!(
            InjectionSpec::Header("X-Api-Key").validate().unwrap(),
            HeaderName::from_static("x-api-key")
        );
        assert_eq!(
            InjectionSpec::BasicPassword { username: "svc" }
                .validate()
                .unwrap(),
            AUTHORIZATION
        );

        let bad_templates: &[InjectionSpec<'_>] = &[
            InjectionSpec::Header("host"),
            InjectionSpec::Header("X-Forwarded-For"),
            InjectionSpec::Header("bad name!"),
            // A `:` moves the base64 field boundary; CR/LF/NUL would split or
            // invalidate the header value.
            InjectionSpec::BasicPassword { username: "a:b" },
            InjectionSpec::BasicPassword {
                username: "svc\r\nX-Evil: 1",
            },
            InjectionSpec::BasicPassword { username: "sv\0c" },
        ];
        for spec in bad_templates {
            assert!(
                matches!(spec.validate(), Err(ApiFailure::BadCredentialEncoding)),
                "template should be rejected before use-accounting"
            );
            assert!(
                matches!(
                    injection_header(spec, b"p4ss"),
                    Err(ApiFailure::BadCredentialEncoding)
                ),
                "a hoisted check must still hold at build time"
            );
        }
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
