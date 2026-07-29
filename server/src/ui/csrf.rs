//! CSRF protection for UI POSTs (addendum #9).
//!
//! Two independent checks, both required on every POST:
//! 1. A per-form token: `base64url(expiry_be8 || hmac)` where the HMAC (keyed
//!    with the keyset MAC key, csrf domain label) covers
//!    `route \0 action_id \0 subject \0 form_state \0 expiry_decimal`.
//!    Single-purpose — a token for one route/object never validates for
//!    another. `form_state` additionally pins any render-time state the page
//!    carries in a hidden field (empty for forms with none), so that marker
//!    cannot be swapped independently of the token. Max age 15 min.
//! 2. Browser metadata: a present `Origin` header must exactly match the
//!    configured `external_url` origin or the request's own Host-derived
//!    origin; with no `Origin`, `Sec-Fetch-Site` must be absent,
//!    `same-origin`, or `none`.

use crate::crypto::{ct_eq, Keyset};
use axum::http::HeaderMap;
use base64::Engine;
use chrono::{DateTime, Utc};

pub const CSRF_TTL_SECONDS: i64 = 15 * 60;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn mac_input(
    route: &str,
    action_id: &str,
    subject: &str,
    form_state: &str,
    expiry_unix: i64,
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(route.as_bytes());
    input.push(0);
    input.extend_from_slice(action_id.as_bytes());
    input.push(0);
    input.extend_from_slice(subject.as_bytes());
    input.push(0);
    input.extend_from_slice(form_state.as_bytes());
    input.push(0);
    input.extend_from_slice(expiry_unix.to_string().as_bytes());
    input
}

/// Mint a form token bound to (route, action id, subject, form state), valid
/// 15 minutes. `form_state` is the render-time state the page shows the
/// operator and echoes back in a hidden field; pass `""` for forms with none.
pub fn issue_token(
    keyset: &Keyset,
    route: &str,
    action_id: &str,
    subject: &str,
    form_state: &str,
    now: DateTime<Utc>,
) -> String {
    let expiry = now.timestamp() + CSRF_TTL_SECONDS;
    let mac = keyset.csrf_mac(&mac_input(route, action_id, subject, form_state, expiry));
    let mut raw = Vec::with_capacity(8 + mac.len());
    raw.extend_from_slice(&expiry.to_be_bytes());
    raw.extend_from_slice(&mac);
    B64.encode(raw)
}

/// Verify a form token: structure, expiry (unexpired AND not further out than
/// the issue TTL), and constant-time MAC comparison over the expected binding.
pub fn verify_token(
    keyset: &Keyset,
    route: &str,
    action_id: &str,
    subject: &str,
    form_state: &str,
    token: &str,
    now: DateTime<Utc>,
) -> bool {
    let Ok(raw) = B64.decode(token) else {
        return false;
    };
    if raw.len() != 8 + 32 {
        return false;
    }
    let expiry = i64::from_be_bytes(raw[..8].try_into().expect("length checked"));
    let ts = now.timestamp();
    if ts >= expiry || expiry - ts > CSRF_TTL_SECONDS {
        return false;
    }
    let expected = keyset.csrf_mac(&mac_input(route, action_id, subject, form_state, expiry));
    ct_eq(&raw[8..], &expected)
}

/// Normalize an origin string (`scheme://host[:port]`) to a comparable
/// (scheme, host, effective-port) triple. Returns None for anything that is
/// not a plain http(s) origin (including `null`).
fn parse_origin(s: &str) -> Option<(String, String, u16)> {
    let url = url::Url::parse(s.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((url.scheme().to_owned(), host, port))
}

/// Browser-metadata half of the POST guard. `external_url` is the configured
/// public base URL; `tls` selects the scheme for the Host-derived origin.
pub fn browser_metadata_ok(external_url: &str, tls: bool, headers: &HeaderMap) -> bool {
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        let Some(got) = parse_origin(origin) else {
            return false; // includes Origin: null
        };
        if let Some(external) = parse_origin(external_url) {
            if got == external {
                return true;
            }
        }
        if let Some(host) = headers
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
        {
            let scheme = if tls { "https" } else { "http" };
            if let Some(own) = parse_origin(&format!("{scheme}://{host}")) {
                if got == own {
                    return true;
                }
            }
        }
        return false;
    }
    // No Origin: fall back to Fetch Metadata.
    match headers.get("sec-fetch-site").map(|v| v.to_str()) {
        None => true,
        Some(Ok(site)) => matches!(site.to_ascii_lowercase().as_str(), "same-origin" | "none"),
        Some(Err(_)) => false,
    }
}

/// Throwaway keyset for tests in this module and for the ui tests that mint
/// approval tokens.
#[cfg(test)]
pub(crate) fn test_keyset() -> Keyset {
    let dir = std::env::temp_dir().join(format!("keychute-csrf-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keyset.json");
    let key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
    let mac = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    std::fs::write(
        &path,
        serde_json::json!({"active": "k0", "keys": {"k0": key}, "mac_key": mac}).to_string(),
    )
    .unwrap();
    let ks = Keyset::load(&path).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    ks
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HOST;
    use chrono::Duration;

    #[test]
    fn csrf_roundtrip() {
        let ks = test_keyset();
        let now = Utc::now();
        let token = issue_token(&ks, "/ui/requests/approve", "req-1", "andrew", "", now);
        assert!(verify_token(
            &ks,
            "/ui/requests/approve",
            "req-1",
            "andrew",
            "",
            &token,
            now
        ));
        // Still valid just before expiry.
        assert!(verify_token(
            &ks,
            "/ui/requests/approve",
            "req-1",
            "andrew",
            "",
            &token,
            now + Duration::seconds(CSRF_TTL_SECONDS - 5),
        ));
    }

    #[test]
    fn csrf_expires() {
        let ks = test_keyset();
        let now = Utc::now();
        let token = issue_token(&ks, "/ui/requests/approve", "req-1", "andrew", "", now);
        assert!(!verify_token(
            &ks,
            "/ui/requests/approve",
            "req-1",
            "andrew",
            "",
            &token,
            now + Duration::seconds(CSRF_TTL_SECONDS + 1),
        ));
    }

    #[test]
    fn csrf_is_single_purpose() {
        let ks = test_keyset();
        let now = Utc::now();
        let token = issue_token(&ks, "/ui/requests/approve", "req-1", "andrew", "", now);
        // Wrong route.
        assert!(!verify_token(
            &ks,
            "/ui/requests/deny",
            "req-1",
            "andrew",
            "",
            &token,
            now
        ));
        // Wrong action id.
        assert!(!verify_token(
            &ks,
            "/ui/requests/approve",
            "req-2",
            "andrew",
            "",
            &token,
            now
        ));
        // Wrong subject.
        assert!(!verify_token(
            &ks,
            "/ui/requests/approve",
            "req-1",
            "mallory",
            "",
            &token,
            now
        ));
    }

    /// A token minted against one render-time form state must not validate for
    /// another: the hidden marker cannot be swapped independently of the token.
    #[test]
    fn csrf_binds_form_state() {
        let ks = test_keyset();
        let now = Utc::now();
        let present = issue_token(&ks, "/ui/requests/approve", "req-1", "andrew", "1", now);
        let absent = issue_token(&ks, "/ui/requests/approve", "req-1", "andrew", "0", now);
        assert_ne!(present, absent);
        for (token, minted_for) in [(&present, "1"), (&absent, "0")] {
            let other = if minted_for == "1" { "0" } else { "1" };
            assert!(verify_token(
                &ks,
                "/ui/requests/approve",
                "req-1",
                "andrew",
                minted_for,
                token,
                now
            ));
            assert!(!verify_token(
                &ks,
                "/ui/requests/approve",
                "req-1",
                "andrew",
                other,
                token,
                now
            ));
            // Dropping the marker entirely is a mismatch too.
            assert!(!verify_token(
                &ks,
                "/ui/requests/approve",
                "req-1",
                "andrew",
                "",
                token,
                now
            ));
        }
    }

    #[test]
    fn csrf_rejects_garbage_and_tampering() {
        let ks = test_keyset();
        let now = Utc::now();
        assert!(!verify_token(&ks, "r", "a", "s", "", "not-base64!!!", now));
        assert!(!verify_token(&ks, "r", "a", "s", "", "", now));
        let token = issue_token(&ks, "r", "a", "s", "", now);
        // Flip a MAC byte.
        let mut raw = B64.decode(&token).unwrap();
        raw[12] ^= 1;
        assert!(!verify_token(
            &ks,
            "r",
            "a",
            "s",
            "",
            &B64.encode(&raw),
            now
        ));
        // Stretch the expiry without re-MACing.
        let mut raw = B64.decode(&token).unwrap();
        let far = (now.timestamp() + 10 * CSRF_TTL_SECONDS).to_be_bytes();
        raw[..8].copy_from_slice(&far);
        assert!(!verify_token(
            &ks,
            "r",
            "a",
            "s",
            "",
            &B64.encode(&raw),
            now
        ));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn origin_check_table() {
        let ext = "https://keychute.example.dev";
        type Case<'a> = (&'a [(&'a str, &'a str)], bool, bool);
        let cases: &[Case] = &[
            // (headers, tls, expected)
            (&[], true, true), // no Origin, no Sec-Fetch-Site
            (&[("origin", "https://keychute.example.dev")], true, true),
            (
                &[("origin", "https://keychute.example.dev:443")],
                true,
                true,
            ),
            (&[("origin", "https://evil.example.com")], true, false),
            (&[("origin", "null")], true, false),
            (&[("origin", "http://keychute.example.dev")], true, false),
            // Host-derived origin (internal URL access).
            (
                &[
                    ("origin", "http://127.0.0.1:8443"),
                    (HOST.as_str(), "127.0.0.1:8443"),
                ],
                false,
                true,
            ),
            (
                &[
                    ("origin", "http://127.0.0.1:8443"),
                    (HOST.as_str(), "127.0.0.1:9999"),
                ],
                false,
                false,
            ),
            // Scheme mismatch against Host-derived origin.
            (
                &[
                    ("origin", "http://127.0.0.1:8443"),
                    (HOST.as_str(), "127.0.0.1:8443"),
                ],
                true,
                false,
            ),
            // Fetch metadata without Origin.
            (&[("sec-fetch-site", "same-origin")], true, true),
            (&[("sec-fetch-site", "none")], true, true),
            (&[("sec-fetch-site", "cross-site")], true, false),
            (&[("sec-fetch-site", "same-site")], true, false),
            // Origin wins over Sec-Fetch-Site when both present.
            (
                &[
                    ("origin", "https://evil.example.com"),
                    ("sec-fetch-site", "same-origin"),
                ],
                true,
                false,
            ),
        ];
        for (pairs, tls, expected) in cases {
            let h = headers(pairs);
            assert_eq!(
                browser_metadata_ok(ext, *tls, &h),
                *expected,
                "case {pairs:?} tls={tls}"
            );
        }
    }
}
