//! Human (approval UI) authentication.
//!
//! Two pluggable modes (docs/IMPLEMENTATION.md "Human authn"):
//! - `static`: `Authorization: Bearer <token>`; SHA-256(token) hex compared in
//!   constant time against the configured hash; subject from config. Dev/e2e.
//! - `oidc`: JWT validation (signature via JWKS, issuer, audience, exp/nbf
//!   with bounded skew) PLUS a mandatory authorization allowlist — subject
//!   list or group-claim membership. Authentication alone never suffices.

use crate::config::{HumanAuthMode, OidcHumanAuth, StaticHumanAuth};
use crate::crypto::ct_eq;
use crate::state::AppState;
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Authenticated + authorized human principal. `subject` is what audit rows
/// record as the actor.
#[derive(Debug, Clone)]
pub struct Operator {
    pub subject: String,
}

/// Authenticate the human behind a UI request. 401 when credentials are
/// missing/invalid, 403 when authenticated but not on the allowlist.
pub async fn authenticate_human(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Operator, StatusCode> {
    let bearer = bearer_token(headers);
    match state.config.human_auth.mode {
        HumanAuthMode::Static => {
            let cfg = state
                .config
                .human_auth
                .r#static
                .as_ref()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            authenticate_static(cfg, bearer)
        }
        HumanAuthMode::Oidc => {
            let cfg = state
                .config
                .human_auth
                .oidc
                .as_ref()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            authenticate_oidc(cfg, bearer).await
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Static-mode check: SHA-256(token) hex vs configured hash, constant time.
pub fn authenticate_static(
    cfg: &StaticHumanAuth,
    bearer: Option<&str>,
) -> Result<Operator, StatusCode> {
    let token = bearer.ok_or(StatusCode::UNAUTHORIZED)?;
    let got = hex::encode(Sha256::digest(token.as_bytes()));
    let want = cfg.token_sha256.to_ascii_lowercase();
    if ct_eq(got.as_bytes(), want.as_bytes()) {
        Ok(Operator {
            subject: cfg.subject.clone(),
        })
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ---------------------------------------------------------------------------
// OIDC

/// Process-wide JWKS cache, keyed by JWKS URL. Refreshed lazily on unknown
/// `kid` AND on age (rate-limited), so key rotation works without a restart.
struct JwksCache {
    inner: tokio::sync::Mutex<HashMap<String, CachedJwks>>,
}

struct CachedJwks {
    keys: HashMap<String, Jwk>,
    fetched_at: Instant,
}

/// Minimum spacing between two JWKS fetches for the same URL. Without it a
/// burst of tokens carrying an unknown/rotated `kid` would hammer the IdP.
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(10);

/// Maximum age of a cached JWKS document, applied even when the requested
/// `kid` IS present. JWKS permits a provider to rotate the key material behind
/// an unchanged `kid`; caching known kids forever would then serve the retired
/// key until the process restarts and every token signed by the replacement
/// would fail — locking the operator out of the approval UI. Ten minutes is
/// short enough that a rotation self-heals quickly and long enough that the
/// steady-state fetch rate is negligible (one request per 10 min per URL).
const JWKS_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// What to do with the cache for a given (jwks_url, kid) lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheAction {
    /// Cached entry holds the kid and is still fresh: use it.
    Serve,
    /// Fetch the JWKS document (unknown kid, or the entry aged out).
    Refresh,
    /// Would refetch, but the last fetch was too recent: reject without a
    /// network call.
    RateLimited,
}

/// Pure cache-expiry decision, factored out so it is testable without network.
/// `cached` is `None` when nothing is cached for the URL, else
/// `(kid_is_present, age_of_the_cached_document)`.
fn cache_action(cached: Option<(bool, Duration)>) -> CacheAction {
    match cached {
        None => CacheAction::Refresh,
        Some((has_kid, age)) => {
            if has_kid && age < JWKS_MAX_AGE {
                CacheAction::Serve
            } else if age < JWKS_MIN_REFRESH {
                CacheAction::RateLimited
            } else {
                CacheAction::Refresh
            }
        }
    }
}

fn jwks_cache() -> &'static JwksCache {
    static CACHE: OnceLock<JwksCache> = OnceLock::new();
    CACHE.get_or_init(|| JwksCache {
        inner: tokio::sync::Mutex::new(HashMap::new()),
    })
}

async fn fetch_jwks(url: &str) -> anyhow::Result<HashMap<String, Jwk>> {
    let set: JwkSet = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(set
        .keys
        .into_iter()
        .filter_map(|k| k.common.key_id.clone().map(|kid| (kid, k)))
        .collect())
}

/// Get the JWK for `kid`, refreshing the cache (rate-limited) when the kid is
/// unknown OR the cached document has aged past [`JWKS_MAX_AGE`].
async fn jwk_for_kid(jwks_url: &str, kid: &str) -> Result<Jwk, StatusCode> {
    let cache = jwks_cache();
    // Held across the fetch on purpose: it collapses a burst of concurrent
    // misses into a single upstream request.
    let mut map = cache.inner.lock().await;
    let entry = map.get(jwks_url);
    let stale_hit = entry.and_then(|c| c.keys.get(kid).cloned());
    let action = cache_action(entry.map(|c| (stale_hit.is_some(), c.fetched_at.elapsed())));
    match action {
        CacheAction::Serve => {
            // `Serve` is only produced when the kid was found.
            return stale_hit.ok_or(StatusCode::UNAUTHORIZED);
        }
        CacheAction::RateLimited => return Err(StatusCode::UNAUTHORIZED),
        CacheAction::Refresh => {}
    }
    match fetch_jwks(jwks_url).await {
        Ok(keys) => {
            let cached = CachedJwks {
                keys,
                fetched_at: Instant::now(),
            };
            let jwk = cached.keys.get(kid).cloned();
            map.insert(jwks_url.to_owned(), cached);
            jwk.ok_or(StatusCode::UNAUTHORIZED)
        }
        Err(err) => {
            tracing::warn!(error = %err, "JWKS fetch failed");
            // Stale-if-error: an IdP outage must not lock the operator out of
            // the approval UI when we still hold a key that validated moments
            // ago. The entry keeps its old `fetched_at`, so the next request
            // retries the fetch as soon as the rate limit allows.
            match stale_hit {
                Some(jwk) => {
                    tracing::warn!(kid, "serving stale cached JWK after failed refresh");
                    Ok(jwk)
                }
                None => Err(StatusCode::UNAUTHORIZED),
            }
        }
    }
}

async fn authenticate_oidc(
    cfg: &OidcHumanAuth,
    bearer: Option<&str>,
) -> Result<Operator, StatusCode> {
    let token = bearer.ok_or(StatusCode::UNAUTHORIZED)?;
    let header = decode_header(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let kid = header.kid.as_deref().ok_or(StatusCode::UNAUTHORIZED)?;
    let jwk = jwk_for_kid(&cfg.jwks_url, kid).await?;
    // The key's algorithm family must match the token header.
    let family_ok = matches!(
        (&jwk.algorithm, header.alg),
        (AlgorithmParameters::RSA(_), Algorithm::RS256)
            | (AlgorithmParameters::EllipticCurve(_), Algorithm::ES256)
    );
    if !family_ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[cfg.issuer.as_str()]);
    validation.set_audience(&[cfg.audience.as_str()]);
    validation.leeway = cfg.clock_skew_seconds;
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let claims = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .claims;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if authorize_claims(cfg, sub, &claims) {
        Ok(Operator {
            subject: sub.to_owned(),
        })
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Mandatory allowlist: subject membership OR group-claim membership.
fn authorize_claims(cfg: &OidcHumanAuth, sub: &str, claims: &serde_json::Value) -> bool {
    if cfg.allowed_subjects.iter().any(|s| s == sub) {
        return true;
    }
    if let Some(group) = &cfg.allowed_group {
        if let Some(values) = claims.get(&cfg.group_claim).and_then(|v| v.as_array()) {
            return values.iter().any(|v| v.as_str() == Some(group.as_str()));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    fn static_cfg(token: &str) -> StaticHumanAuth {
        StaticHumanAuth {
            token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
            subject: "andrew".into(),
        }
    }

    #[test]
    fn static_auth_accepts_correct_token() {
        let cfg = static_cfg("s3cret-token");
        let op = authenticate_static(&cfg, Some("s3cret-token")).unwrap();
        assert_eq!(op.subject, "andrew");
    }

    #[test]
    fn static_auth_accepts_uppercase_config_hash() {
        let mut cfg = static_cfg("tok");
        cfg.token_sha256 = cfg.token_sha256.to_ascii_uppercase();
        assert!(authenticate_static(&cfg, Some("tok")).is_ok());
    }

    #[test]
    fn static_auth_rejects_wrong_or_missing_token() {
        let cfg = static_cfg("right");
        assert_eq!(
            authenticate_static(&cfg, Some("wrong")).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            authenticate_static(&cfg, None).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn bearer_extraction() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, "bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn jwks_cache_refreshes_when_nothing_is_cached() {
        assert_eq!(cache_action(None), CacheAction::Refresh);
    }

    #[test]
    fn jwks_cache_serves_a_fresh_known_kid() {
        assert_eq!(
            cache_action(Some((true, Duration::from_secs(0)))),
            CacheAction::Serve
        );
        assert_eq!(
            cache_action(Some((true, JWKS_MAX_AGE - Duration::from_secs(1)))),
            CacheAction::Serve
        );
    }

    #[test]
    fn jwks_cache_expires_a_known_kid_so_same_kid_rotation_recovers() {
        // The regression this guards: a provider rotating key material behind
        // an unchanged `kid` must not be served from cache forever.
        assert_eq!(
            cache_action(Some((true, JWKS_MAX_AGE))),
            CacheAction::Refresh
        );
        assert_eq!(
            cache_action(Some((true, JWKS_MAX_AGE + Duration::from_secs(60)))),
            CacheAction::Refresh
        );
    }

    #[test]
    fn jwks_cache_rate_limits_unknown_kids() {
        // Unknown kid, fetched moments ago: reject without touching the IdP.
        assert_eq!(
            cache_action(Some((false, Duration::from_secs(0)))),
            CacheAction::RateLimited
        );
        assert_eq!(
            cache_action(Some((false, JWKS_MIN_REFRESH - Duration::from_millis(1)))),
            CacheAction::RateLimited
        );
        // Past the floor, one refresh is allowed.
        assert_eq!(
            cache_action(Some((false, JWKS_MIN_REFRESH))),
            CacheAction::Refresh
        );
    }

    #[test]
    fn jwks_refresh_floor_is_below_the_max_age() {
        // Otherwise an aged-out known kid would be rejected as rate-limited
        // instead of triggering the refresh it needs.
        assert!(JWKS_MIN_REFRESH < JWKS_MAX_AGE);
    }

    #[test]
    fn allowlist_by_subject_and_group() {
        let cfg = OidcHumanAuth {
            issuer: "https://iss".into(),
            audience: "keychute".into(),
            jwks_url: "https://iss/jwks".into(),
            allowed_subjects: vec!["alice".into()],
            allowed_group: Some("keychute-admins".into()),
            group_claim: "groups".into(),
            clock_skew_seconds: 60,
        };
        let with_group = serde_json::json!({ "groups": ["x", "keychute-admins"] });
        let wrong_group = serde_json::json!({ "groups": ["x"] });
        let no_groups = serde_json::json!({});
        assert!(authorize_claims(&cfg, "alice", &no_groups));
        assert!(authorize_claims(&cfg, "bob", &with_group));
        assert!(!authorize_claims(&cfg, "bob", &wrong_group));
        assert!(!authorize_claims(&cfg, "bob", &no_groups));
        // Group claim must be an array; a plain string never matches.
        let string_claim = serde_json::json!({ "groups": "keychute-admins" });
        assert!(!authorize_claims(&cfg, "bob", &string_claim));
    }
}
