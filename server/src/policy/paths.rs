//! Path canonicalization and prefix matching (DESIGN §4, IMPLEMENTATION
//! "Path canonicalization").
//!
//! Rules: percent-decode exactly once; reject anything ambiguous (bad or
//! partial escapes, encoded `/` or `\`, raw `\`, `.`/`..` segments, non-UTF8,
//! control characters, duplicate slashes). Duplicate slashes (`//`) are
//! rejected outright: an all-slash prefix would strip to the empty string in
//! `prefix_matches` and become unconstrained, and upstream servers disagree on
//! whether `//` aliases `/`, so the ambiguity is refused at the door.

/// Canonicalize the raw path portion of a URL (no query string).
///
/// Returns the decoded canonical path (always starting with `/`), or a static
/// error message describing the rejection.
pub fn canonicalize(raw: &str) -> Result<String, &'static str> {
    if !raw.starts_with('/') {
        return Err("path must start with '/'");
    }

    // Percent-decode exactly once, byte-wise.
    let bytes = raw.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'%' => {
                if i + 3 > bytes.len() {
                    return Err("truncated percent escape");
                }
                let (h, l) = (bytes[i + 1], bytes[i + 2]);
                let hv = hex_val(h).ok_or("invalid percent escape")?;
                let lv = hex_val(l).ok_or("invalid percent escape")?;
                let v = (hv << 4) | lv;
                match v {
                    b'/' => return Err("encoded '/' in path"),
                    b'\\' => return Err("encoded '\\' in path"),
                    _ => decoded.push(v),
                }
                i += 3;
            }
            b'\\' => return Err("raw '\\' in path"),
            _ => {
                decoded.push(b);
                i += 1;
            }
        }
    }

    // UTF-8 validity after decoding.
    let s = String::from_utf8(decoded).map_err(|_| "path is not valid UTF-8 after decoding")?;

    // Control characters (C0 range and DEL) are never legitimate in a path.
    if s.chars().any(|c| c.is_control()) {
        return Err("control character in path");
    }

    // Dot segments: the leading '/' guarantees split element 0 is "".
    // Each segment is judged by the portion BEFORE any ';' (path parameters):
    // servlet-family upstreams strip `;params` and only then normalize, so a
    // segment `..;jsessionid=x` — or its encoded spelling `..%3b`, which the
    // decode above has already turned into `..;` — would land on `..`
    // upstream and escape the approved prefix scope.
    if s.split('/').any(|seg| {
        let base = seg.split(';').next().unwrap_or(seg);
        base == "." || base == ".."
    }) {
        return Err("dot segment in path");
    }

    // Duplicate slashes create empty segments; an all-slash prefix would
    // otherwise strip to nothing and match everything. Reject outright.
    if s.contains("//") {
        return Err("duplicate slash in path");
    }

    Ok(s)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Prefix match at `/` segment boundaries only. Both arguments must already be
/// canonical. `"/"` matches everything; otherwise the prefix (trailing slashes
/// stripped) matches iff the path equals it or continues it at a `/` boundary,
/// so `/v1/account` does NOT match `/v1/account-delete`.
pub fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let p = prefix.trim_end_matches('/');
    if p.is_empty() {
        // e.g. "//" — not canonical (canonicalize rejects duplicate slashes);
        // fail closed rather than treating an all-slash prefix as root.
        return false;
    }
    path == p || (path.len() > p.len() && path.as_bytes()[p.len()] == b'/' && path.starts_with(p))
}

// NOTE: there is deliberately no re-encoder here. The outbound request line is
// built by `proxy::outbound_url`, which hands the canonical (decoded) path to
// `url::Url::set_path` and lets the `url` crate do the single encode. A second
// encoder applied on top of that would double-encode and send the credential
// to a different upstream resource than the grant authorized.
