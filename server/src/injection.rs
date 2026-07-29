//! Injection-template validation, shared by the admin UI (`POST /ui/secrets`)
//! and the client deposit endpoint (`POST /v1/secrets`).
//!
//! The template decides where a credential is placed on the brokered leg, so a
//! bad one is a security bug, not a cosmetic one: a header that the proxy also
//! synthesizes (or that a hop rewrites) could smuggle the credential somewhere
//! nobody approved. Both writers therefore go through this one function.

/// Headers the injection template may never target: hop-by-hop headers, the
/// proxy's own auth headers, and the routing/override headers an upstream may
/// act on. `x-forwarded-*` is refused by prefix.
const RESERVED: &[&str] = &[
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

/// Addendum #4/#17 subset: validate a supplied injection template.
///
/// Returns `(injection_kind, injection_header, injection_username)`. Callers
/// have one free-text field (`injection_header`), routed to the header column
/// for kind 'header' and to `injection_username` for kind 'basic' (migration
/// 0003). 'basic-password' is accepted as an alias for 'basic' (both spellings
/// are also valid in the DB CHECK since migration 0004).
///
/// Errors are `&'static str` so they can be surfaced verbatim by both the UI
/// (`400` page) and the API (`invalid-request`) without ever embedding
/// caller-supplied text in the message.
#[allow(clippy::type_complexity)]
pub fn validate_injection(
    kind: &str,
    header: Option<&str>,
) -> Result<(String, Option<String>, Option<String>), &'static str> {
    match kind {
        "bearer" => Ok(("bearer".into(), None, None)),
        "header" => {
            let name = header.ok_or("injection kind 'header' requires a header name")?;
            let lower = name.to_ascii_lowercase();
            let valid_token = !name.is_empty()
                && name.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(
                            b,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )
                });
            if !valid_token {
                return Err("injection header is not a valid header name");
            }
            if RESERVED.contains(&lower.as_str()) || lower.starts_with("x-forwarded-") {
                return Err("injection header is reserved");
            }
            Ok(("header".into(), Some(name.to_owned()), None))
        }
        "basic" | "basic-password" => {
            let username = header.ok_or("injection kind 'basic-password' requires a username")?;
            if username.contains(':') || username.chars().any(|c| c.is_control()) {
                return Err("invalid basic-auth username");
            }
            // Username goes to injection_username; injection_header stays NULL
            // (the proxy still falls back to injection_header for old rows).
            Ok(("basic".into(), None, Some(username.to_owned())))
        }
        _ => Err("unknown injection kind"),
    }
}
