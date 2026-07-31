//! `keychute curl` — brokered HTTP (CUJ 1, tier 0): the credential is attached
//! by the server and never enters this container.
//!
//! The mnemonic is deliberate: wherever an agent would reach for
//! `curl https://api.example.com/v1/thing -H 'Authorization: Bearer …'`, it
//! runs `keychute curl --secret example-api-token https://api.example.com/v1/thing`
//! instead and never handles the token at all. Unlike `request`, nothing
//! secret passes through this process: stdout carries the UPSTREAM RESPONSE,
//! which is ordinary data, so the staging-file discipline that tier 2 needs
//! does not apply here.
//!
//! The flow is the same three steps as `request` — create an access request,
//! wait for the human, then exercise the grant — except the grant is exercised
//! against `POST /v1/grants/{id}/proxy…` and what comes back is the upstream's
//! own response.
//!
//! The URL is what the grant is derived from: its origin becomes the single
//! approved origin, its method the single approved method, and its path the
//! path prefix. Approving one `keychute curl` therefore approves exactly that
//! call — not the host.
//!
//! # Scope: curl-SHAPED, not a curl
//!
//! This is a brokered-access client that borrows curl's spelling so an agent
//! reaching for `curl` does not have to learn a second vocabulary. It is not a
//! curl implementation and is not on a path to becoming one. The flags below
//! are the whole surface; the ones that exist behave as curl does, and
//! anything absent is absent on purpose.
//!
//! That boundary is the useful property, not a gap to close. Every additional
//! curl behaviour is either irrelevant here (`-L`: redirects are never
//! followed, by design), incompatible with a brokered grant (`-u`, `--proxy`:
//! the credential and the route are the server's to choose), or an
//! open-ended surface with no natural stopping point (`--form`, cookie jars,
//! `@` globbing, `--compressed`, `--retry`). Adding them would trade a small
//! auditable command for a large one whose behaviour an operator can no
//! longer predict from the approval page.
//!
//! Unknown flags therefore fail at the parser rather than being silently
//! ignored or approximated — an agent that needs something outside this
//! surface should find out immediately, not discover it from a request that
//! went out differently than it read.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use keychute_types::{
    Constraints, CreateAccessRequest, GrantInfo, Mechanism, Origin, RequestContext, RequestState,
};
use uuid::Uuid;

use crate::{
    api_error_message, build_structured_context, classify_gone, create_access_request, fail,
    validate_idempotency_key, wait_for_resolution, CliResult, Config, Failure, EXIT_CONFIG,
    EXIT_DENIED, EXIT_OTHER,
};

/// Default bound on how much of a `@file` / `@-` body this command will read
/// into memory. Not an attempt to predict the server's answer: the real cap is
/// `limits.proxy_max_body_bytes`, which is per-deployment and not discoverable
/// from here, so the server stays the authority and a body under this bound is
/// still free to come back 413.
///
/// What this bound is actually for is the read itself — a mistaken
/// `-d @/dev/zero`, or a producer upstream in the pipe that never stops, must
/// not be slurped into memory before anyone checks its size. The default
/// matches the server's own default so the common deployment agrees with it;
/// [`MAX_BODY_ENV`] moves it for a deployment that configured something else.
const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// The server's fixed upper bound on a grant's lifetime (`requests.rs`). It is
/// not deployment-configurable, so refusing a longer `--ttl` locally costs
/// nothing and saves an invocation that would be rejected on arrival.
const MAX_TTL_SECONDS: u64 = 30 * 24 * 3600;

/// The server's remaining fixed bounds (`requests.rs`), mirrored for the same
/// reason as [`MAX_TTL_SECONDS`]: none are deployment-configurable, so a value
/// past them is certain to be refused and there is nothing to gain by making
/// the round trip — or by reading stdin first.
const MAX_SERVER_USES: u32 = i32::MAX as u32;
const MAX_SECRET_NAME_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 4 * 1024;
/// The cap the server applies to each constraint list — origins, methods and
/// path prefixes alike.
const MAX_CONSTRAINT_ENTRIES: usize = 32;

/// Ceiling on `--timeout`. Waiting longer than the longest grant can live is
/// meaningless, and the deadline is an `Instant` — a value near `u64::MAX`
/// seconds overflows the addition and panics, which is no way to report a bad
/// argument (least of all after `-d @-` has already eaten its input).
const MAX_APPROVAL_WAIT_SECONDS: u64 = MAX_TTL_SECONDS;

/// Overrides [`DEFAULT_MAX_BODY_BYTES`], for a deployment whose
/// `limits.proxy_max_body_bytes` is not the default.
const MAX_BODY_ENV: &str = "KEYCHUTE_MAX_BODY_BYTES";

/// The effective local read bound. An unparseable or zero value is a config
/// error rather than a silent fallback: quietly using a different bound than
/// the one asked for is how a body gets truncated without anyone noticing.
fn max_body_bytes() -> CliResult<usize> {
    parse_max_body(std::env::var(MAX_BODY_ENV).ok().as_deref())
}

/// The parsing half, kept pure so it is testable without mutating process
/// environment that sibling tests read concurrently.
fn parse_max_body(raw: Option<&str>) -> CliResult<usize> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_MAX_BODY_BYTES);
    };
    match raw.trim().parse::<usize>() {
        // The reader needs `limit + 1` to tell "at the bound" from "over it".
        // A value with no room for that would wrap in release builds and make
        // `take(0)` read NOTHING — turning a side-effecting request into one
        // with an empty body, silently.
        Ok(n) if n > 0 && n < usize::MAX => Ok(n),
        _ => Err(fail(
            EXIT_CONFIG,
            format!("{MAX_BODY_ENV} must be a positive byte count, got {raw:?}"),
        )),
    }
}

/// Header the server stamps on its OWN error responses (never on a proxied
/// upstream response — `proxy.rs` strips it from upstream headers precisely so
/// an upstream cannot forge one). Its presence is what separates "Keychute
/// refused" from "the upstream answered 403", which are the same status code
/// and must not be the same exit code.
const KEYCHUTE_ERROR_HEADER: &str = "x-keychute-error";

/// Caller headers the broker will not forward (server `STRIP_LIST`), plus the
/// `x-forwarded-` family matched by prefix. Passing one is not an error — the
/// request still goes — but it silently would not arrive, so say so.
const STRIPPED_HEADERS: &[&str] = &[
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

#[derive(clap::Args)]
pub(crate) struct CurlArgs {
    /// Target URL. https:// only — brokered origins are https by construction,
    /// so the credential cannot be sent in the clear.
    pub url: String,
    /// Name of the Keychute secret to authenticate with. The value stays
    /// server-side; the server attaches it per the secret's injection
    /// template. Required unless --grant-id names an existing grant.
    #[arg(long)]
    pub secret: Option<String>,
    /// HTTP method (default GET, or POST when a body is supplied).
    #[arg(short = 'X', long = "request", value_name = "METHOD")]
    pub method: Option<String>,
    /// Extra request header, `Name: value`. Repeatable. As in curl, `Name:`
    /// with nothing after the colon removes the header rather than sending an
    /// empty one, and `Name;` sends it with an empty value.
    #[arg(short = 'H', long = "header", value_name = "LINE")]
    pub headers: Vec<String>,
    /// Request body. `@path` reads a file, `@-` reads stdin (curl's spelling).
    /// Repeatable: pieces are joined with `&`, as curl does. Unlike curl, this
    /// does NOT imply a Content-Type: pass one with -H.
    #[arg(short = 'd', long = "data", value_name = "DATA")]
    pub data: Vec<String>,
    /// Request body taken literally, `@` and all. Repeatable, joined with `&`.
    #[arg(long = "data-raw", value_name = "DATA", conflicts_with = "data")]
    pub data_raw: Vec<String>,
    /// Like -d, but file and stdin input is sent byte for byte — no CR/LF
    /// stripping (curl's --data-binary). Repeatable, joined with `&`.
    ///
    /// Unlike curl, this may not be MIXED with -d/--data-raw in one command:
    /// curl merges the pieces in the order they appear on the command line,
    /// and reproducing that ordering across different flags is not something
    /// this parser can do faithfully. A refusal is better than a body whose
    /// fields are silently in a different order than curl would have sent.
    #[arg(
        long = "data-binary",
        value_name = "DATA",
        conflicts_with_all = ["data", "data_raw"]
    )]
    pub data_binary: Vec<String>,
    /// Write the response body here instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Prepend the response status line and headers to the output.
    #[arg(short = 'i', long = "include")]
    pub include: bool,
    /// Exit non-zero on an upstream status >= 400 and suppress its body
    /// (curl's -f). Without it, an upstream error is a successful call that
    /// returned an error document, and exits 0.
    #[arg(short = 'f', long = "fail")]
    pub fail: bool,
    /// Human-readable reason, shown verbatim on the approval page.
    #[arg(long, default_value = "")]
    pub reason: String,
    /// Requested grant TTL in seconds. Short by default: a grant outlives the
    /// call it was approved for, so the default is "long enough for this one".
    #[arg(long, default_value_t = 300)]
    pub ttl: u64,
    /// Requests this grant may serve. 0 means no cap (TTL only) — an explicit
    /// choice, since the default of 1 makes an approval cover one call.
    #[arg(long, default_value_t = 1)]
    pub max_uses: u32,
    /// How long to wait for approval before giving up, in seconds.
    #[arg(long, default_value_t = 900)]
    pub timeout: u64,
    /// Deadline for the proxied call itself, in seconds. Fractional, as curl
    /// takes it (`--max-time 0.5`); 0 disables the limit.
    #[arg(long, default_value_t = 120.0)]
    pub max_time: f64,
    /// Idempotency key for the access request (random UUID if omitted).
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Exercise an existing approved grant instead of asking for a new one.
    /// Printed by a previous `keychute curl` on approval.
    #[arg(long, value_name = "UUID")]
    pub grant_id: Option<String>,
    /// Path prefix the grant should cover (repeatable). Defaults to the URL's
    /// own path, which is the narrowest thing that permits this call.
    #[arg(long = "path-prefix", value_name = "PATH")]
    pub path_prefixes: Vec<String>,
    /// Additional method the grant should cover (repeatable). Only useful with
    /// --max-uses, to make one approval cover a sequence of calls.
    #[arg(long = "allow-method", value_name = "METHOD")]
    pub allow_methods: Vec<String>,
}

/// What the URL says about where this call goes: the parts the grant is
/// derived from, plus the raw path/query forwarded through the proxy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub origin: Origin,
    /// Raw (still percent-encoded) path, always starting with `/`. The server
    /// canonicalizes it and rejects ambiguous encodings; sending the decoded
    /// form here would launder exactly what it means to reject.
    pub path: String,
    pub query: Option<String>,
}

impl Target {
    /// How the target reads on the approval page and in stderr diagnostics.
    fn display(&self) -> String {
        let mut s = format!("{}{}", self.origin.to_display(), self.path);
        if let Some(q) = &self.query {
            s.push('?');
            s.push_str(q);
        }
        s
    }
}

/// Split a URL into the grant's origin and the proxied path/query.
///
/// Rejections here are all cases where approving the URL would not mean what
/// it looks like it means: a plaintext scheme (the credential would leave
/// Keychute unencrypted), userinfo (`https://real.example@attacker.example/`
/// reads as one host and targets another), or a host `Origin::parse` refuses
/// (wildcards, noncanonical numeric IPv4 that URL parsers retarget).
pub(crate) fn parse_target(raw: &str) -> Result<Target, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid URL {raw:?}: {e}"))?;
    match url.scheme() {
        "https" => {}
        "http" => {
            return Err(format!(
                "refusing plaintext http:// target {raw:?}: brokered grants are https-only, \
                 so the injected credential is never sent in the clear"
            ))
        }
        other => {
            return Err(format!(
                "unsupported URL scheme {other:?} in {raw:?}: use https://"
            ))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "refusing URL with embedded credentials {raw:?}: the host a human would read \
             is not the host it targets, and Keychute supplies the credential anyway"
        ));
    }
    // Characters the WHATWG parser makes DISAPPEAR rather than reject, which
    // is the backslash problem in a quieter form: `raw_path_and_query` keeps
    // them, the approval page and the call-binding hash cover the spelling
    // with them in, and then `proxy_call` re-parses the assembled URL and
    // sends it without them. A query displayed as `amount=1\n000` would arrive
    // upstream as `amount=1000` — a different call than the one that was
    // approved, with no diagnostic anywhere.
    //
    // Two rules, because the parser has two ways of doing it. Tab, CR and LF
    // are deleted from ANYWHERE in the input; every other C0 control and DEL
    // is deleted only at the ends, along with spaces — so `?to=alice%00`
    // survives this check with the NUL in the approval text and loses it on
    // the wire. Refusing the whole class costs nothing: none of it is legal in
    // a URL unencoded, and the encoded spelling always remains available.
    if let Some(bad) = raw.chars().find(|c| c.is_ascii_control() || *c == '\u{7f}') {
        return Err(format!(
            "refusing URL containing {bad:?} {raw:?}: URL parsers silently DELETE control \
             characters — tab, CR and LF anywhere, the rest at either end — so the target \
             an operator would approve is not the target that would be sent. \
             Percent-encode it (%09, %0D, %0A, %00 …) if it is really meant."
        ));
    }
    // Spaces ANYWHERE, not just at the ends. At the ends the parser trims them;
    // in the middle it keeps the character but re-spells it, so
    // `?account=a b` is displayed and hashed with the space and arrives
    // upstream as `a%20b`. Either way the approved spelling is not the
    // transmitted one, which is the whole objection. curl 8.5.0 refuses the lot
    // as a malformed URL (exit 3) rather than encoding on the caller's behalf.
    if raw.contains(' ') {
        return Err(format!(
            "refusing URL containing a space {raw:?}: parsers trim spaces at the ends and \
             re-encode them in the middle (a query of `a b` is sent as `a%20b`), so the \
             approved spelling is not the one that would be sent. Percent-encode it (%20) \
             if it is really part of the target."
        ));
    }
    if raw.contains('\\') {
        // The WHATWG parser treats `\` as a path separator; the raw extractor
        // below does not, and neither does the server. For
        // `https://api.example\admin` the parser reads the path as `/admin`
        // while the raw scanner reads `/` — the URL means two different things
        // depending on who reads it, which is exactly the ambiguity approval
        // cannot survive. The server's `policy::paths::canonicalize` refuses
        // raw backslashes too; refuse here so the human is never asked to
        // approve a target whose meaning is disputed.
        return Err(format!(
            "refusing URL with a backslash {raw:?}: URL parsers treat `\\` as a path \
             separator and Keychute does not, so the target is ambiguous. Use `/`. \
             (Keychute rejects `\\` in a path in every spelling, encoded included; \
             in a query string, percent-encode it as %5C.)"
        ));
    }
    if url.fragment().is_some() {
        return Err(format!(
            "URL fragment in {raw:?} is never sent to a server; drop it"
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("URL {raw:?} has no host"))?;
    // Assembled and handed to `Origin::parse` whole rather than parsed for the
    // host and then patched: assigning `origin.port` directly walks around
    // that function's own port checks, and `:0` is a port a URL parser accepts
    // and `Origin` rejects. One validator, no second path past it.
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let origin = Origin::parse(&authority)?;
    // Path and query come from the ORIGINAL string, not from `url`: the URL
    // parser resolves dot segments at parse time, including ENCODED ones, so
    // `url.path()` for `/a/%2e%2e/admin` is already `/admin`. Taking it from
    // there would send a request to a resource the caller did not name and
    // launder past `policy::paths::canonicalize`, which exists to reject that
    // exact input. The authority is still the parser's answer — that is what
    // it is good for, and `Origin::parse` re-checks it.
    let (path, query) = raw_path_and_query(raw);
    // The last of the same family, and the general case of the space rule
    // above: characters the parser neither rejects nor deletes but RE-SPELLS.
    // `?q="x"` is displayed and hashed with the quotes and arrives upstream as
    // `%22x%22`, and `é` arrives as `%C3%A9` — a distinction an upstream that
    // signs or logs the raw request target can see. curl sends both verbatim,
    // so this is a divergence from curl and from the approval text at once.
    //
    // The sets are the parser's own, pinned by
    // `every_character_the_parser_respells_is_refused` — which derives them
    // from `Url::parse` at test time, so a url-crate change fails the test
    // rather than silently reopening the gap.
    if let Some(bad) = path
        .chars()
        .find(|c| !c.is_ascii() || PATH_RESPELLED.contains(*c))
    {
        return Err(respelled_error(bad, raw));
    }
    if let Some(bad) = query
        .as_deref()
        .unwrap_or("")
        .chars()
        .find(|c| !c.is_ascii() || QUERY_RESPELLED.contains(*c))
    {
        return Err(respelled_error(bad, raw));
    }
    Ok(Target {
        origin,
        path,
        query,
    })
}

/// Characters `Url::parse` percent-encodes rather than passing through, per
/// component. Non-ASCII is re-spelled in both and handled separately.
const PATH_RESPELLED: &str = "\"<>`{}";
const QUERY_RESPELLED: &str = "\"'<>";

fn respelled_error(bad: char, raw: &str) -> String {
    format!(
        "refusing URL containing {bad:?} {raw:?}: URL parsers percent-encode it on the way \
         out, so the target an operator approves is not the one that would be sent \
         (an upstream that signs or logs the raw target can tell them apart). \
         Percent-encode it yourself if it is really part of the target."
    )
}

/// The path and query EXACTLY as written, without the normalization a URL
/// parser applies. Assumes the scheme/authority have already been validated by
/// one, which is why it can simply scan past `://`.
fn raw_path_and_query(raw: &str) -> (String, Option<String>) {
    let after_scheme = match raw.find("://") {
        Some(i) => &raw[i + 3..],
        None => raw,
    };
    // The authority runs to the first '/', '?' or '#'.
    let start = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let rest = &after_scheme[start..];
    let (path_part, query_part) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q.split('#').next().unwrap_or(q))),
        None => (rest.split('#').next().unwrap_or(rest), None),
    };
    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part.to_string()
    };
    (path, query_part.map(|q| q.to_string()))
}

/// Normalize and validate an HTTP method. Uppercased because that is the form
/// the grant stores, the server compares, and the audit log records.
pub(crate) fn normalize_method(m: &str) -> Result<String, String> {
    let upper = m.trim().to_ascii_uppercase();
    reqwest::Method::from_bytes(upper.as_bytes())
        .map_err(|_| format!("invalid HTTP method {m:?}"))?;
    if upper == "TRACE" {
        // The server refuses this unconditionally (a TRACE-capable upstream
        // echoes the request back, credential header included). Say why here
        // rather than spending an approval to be told.
        return Err(
            "TRACE is never proxied: an upstream that echoes the request would \
             reflect the injected credential back to this container"
                .into(),
        );
    }
    Ok(upper)
}

/// Split `Name: value`. Leading whitespace on the value is dropped, exactly as
/// curl does; the name must be a real header token.
///
/// Three spellings, all curl's:
///   * `Name: value` — send it.
///   * `Name:` (nothing after the colon) — *remove* the header. curl uses this
///     to suppress its own defaults; here there are no defaults to suppress, so
///     it resolves to "do not send", returning `None`. What it must NOT do is
///     send `Name` with an empty value: an upstream that distinguishes an
///     absent header from a present-but-empty one would then see a different
///     request than the curl line it was copied from.
///   * `Name;` — send it with an empty value. The only way to spell that, again
///     as curl does, since `Name:` means removal.
pub(crate) fn parse_header(line: &str) -> Result<Option<(String, String)>, String> {
    let (name, value) = match line.split_once(':') {
        Some((name, value)) => (name, Some(value)),
        // No colon: the `Name;` form, or a malformed line.
        None => match line.trim_end_matches([' ', '\t']).strip_suffix(';') {
            Some(name) => (name, None),
            None => return Err(format!("header {line:?} is not in `Name: value` form")),
        },
    };
    let name = trim_ows(name);
    if name.is_empty() {
        return Err(format!("header {line:?} has an empty name"));
    }
    reqwest::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("invalid header name in {line:?}"))?;
    let value = match value {
        // `Name:` — removal, and nothing here adds headers to remove. Only
        // ASCII space and tab count as the emptiness curl means: `X-Sig:\u{a0}`
        // sends the two NBSP bytes in curl 8.5.0, it does not remove anything.
        Some(v) if v.trim_start_matches([' ', '\t']).is_empty() => return Ok(None),
        // Leading OWS only, and ASCII only. `str::trim_start` would also eat
        // NBSP, U+2007 and the rest of the Unicode whitespace class, which are
        // ordinary value bytes to curl and to HTTP — silently shortening a
        // signature or an opaque token copied from a working curl line.
        // Trailing bytes were already preserved, as curl preserves them.
        Some(v) => v.trim_start_matches([' ', '\t']),
        // `Name;` — deliberately empty.
        None => "",
    };
    reqwest::header::HeaderValue::from_str(value)
        .map_err(|_| format!("invalid header value in {line:?}"))?;
    Ok(Some((name.to_ascii_lowercase(), value.to_string())))
}

/// HTTP's optional whitespace: ASCII space and tab, and nothing else. Used
/// instead of `str::trim`, whose Unicode whitespace class includes bytes that
/// are legitimate header content.
fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Would the broker drop this header? Not fatal, but silence would be worse:
/// the call would go out looking like it carried something it did not.
pub(crate) fn is_stripped_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    STRIPPED_HEADERS.contains(&n.as_str()) || n.starts_with("x-forwarded-")
}

/// Header names nominated as hop-by-hop by a caller-supplied `Connection`
/// value (comma-separated tokens, case-insensitive), lowercased.
pub(crate) fn connection_nominated(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n == "connection")
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// The constraints a grant needs to permit exactly this call.
pub(crate) fn constraints_for(
    target: &Target,
    method: &str,
    extra_methods: &[String],
    path_prefixes: &[String],
    ttl: u64,
    max_uses: u32,
) -> Result<Constraints, String> {
    let mut methods = vec![method.to_string()];
    for m in extra_methods {
        let m = normalize_method(m)?;
        if !methods.contains(&m) {
            methods.push(m);
        }
    }
    let prefixes = if path_prefixes.is_empty() {
        vec![target.path.clone()]
    } else {
        for p in path_prefixes {
            if !p.starts_with('/') {
                return Err(format!("path prefix {p:?} must start with '/'"));
            }
        }
        // A prefix set that excludes the call itself would spend an operator's
        // approval on a grant whose very first use is a guaranteed 403. The
        // server checks the CANONICAL path against the CANONICAL prefixes it
        // stored (`api/requests.rs` canonicalizes every submitted prefix), so
        // both sides have to be canonicalized here too — comparing a canonical
        // target against a still-encoded prefix would reject
        // `--path-prefix /files/a%20b` for a URL of `/files/a%20b`, which is
        // the same call.
        //
        // A prefix with no canonical form is a local configuration error, not
        // something to defer: `api/requests.rs` canonicalizes every submitted
        // prefix and rejects the whole request if one fails, so the call cannot
        // succeed however it is approved. Dropping it from the comparison
        // instead would let preflight pass and `-d @-` block on a producer for
        // an invocation already certain to be refused.
        for p in path_prefixes {
            if canonical_path(p).is_none() {
                return Err(format!(
                    "--path-prefix {p:?} is one the broker refuses: it must percent-decode \
                     once to valid UTF-8, with no encoded '/' or '\\', no '.' or '..' segment \
                     (judged before any ';'), no control characters and no '//'"
                ));
            }
        }
        if let Some(canonical_target) = canonical_path(&target.path) {
            let canonical_prefixes: Vec<String> = path_prefixes
                .iter()
                .filter_map(|p| canonical_path(p))
                .collect();
            if !canonical_prefixes.is_empty()
                && !canonical_prefixes
                    .iter()
                    .any(|p| path_covered(p, &canonical_target))
            {
                return Err(format!(
                    "--path-prefix {} does not cover {canonical_target}, so the approved \
                     grant could not serve this call",
                    path_prefixes.join(", ")
                ));
            }
        }
        path_prefixes.to_vec()
    };
    Ok(Constraints {
        origins: vec![target.origin.clone()],
        methods,
        path_prefixes: prefixes,
        ttl_seconds: ttl,
        // 0 is the documented spelling of "no cap": the server treats a
        // missing max_uses as unlimited-within-TTL for brokered grants, and
        // rejects a literal 0.
        max_uses: (max_uses > 0).then_some(max_uses),
    })
}

/// Read the request body, following curl's rules so that swapping `curl` for
/// `keychute curl` sends the same bytes:
///
/// * `-d @path` / `-d @-` read a file or stdin **with CR and LF stripped** —
///   curl does this so a form body typed into a file does not carry the
///   editor's line breaks. A body that must survive intact is what
///   `--data-binary` is for.
/// * `-d value` and `--data-raw value` take the argument literally
///   (`--data-raw` also declines to treat a leading `@` as a file).
///
/// Opens its own sources, which is what makes it test-only: `run_curl` has to
/// open them before `open_output` runs, so it drives `read_body_with`.
#[cfg(test)]
fn read_body(args: &CurlArgs) -> CliResult<Option<Vec<u8>>> {
    read_body_bounded(args, max_body_bytes()?)
}

/// Which pieces make up the body, and how they are read. `--data-raw` takes
/// every piece literally; the other two read `@`. Exactly one flavour can be
/// present (clap enforces it), so there is no cross-flag ordering to get
/// wrong.
fn body_pieces(args: &CurlArgs) -> Option<(&Vec<String>, bool, bool)> {
    if !args.data_raw.is_empty() {
        Some((&args.data_raw, false, false))
    } else if !args.data.is_empty() {
        Some((&args.data, true, true))
    } else if !args.data_binary.is_empty() {
        Some((&args.data_binary, true, false))
    } else {
        None
    }
}

/// Open every file-backed body piece, in the order given. One entry per piece;
/// `None` for a literal piece and for `@-`, which is stdin.
///
/// Separate from the reading so it can run BEFORE `open_output`. With
/// `-d @payload -o payload` the output would otherwise CREATE the input, and
/// the missing-file error that invocation deserves would become an empty body
/// sent under a real approval. Opening first judges the input against the
/// filesystem as the caller found it.
///
/// Nothing is read here, and `@-` is not touched: stdin is still consumed only
/// once every check has passed.
fn open_body_sources(args: &CurlArgs) -> CliResult<Vec<Option<std::fs::File>>> {
    let Some((pieces, reads_at, _)) = body_pieces(args) else {
        return Ok(Vec::new());
    };
    let mut opened = Vec::with_capacity(pieces.len());
    for piece in pieces {
        opened.push(match piece.strip_prefix('@') {
            Some("-") if reads_at => None,
            Some(src) if reads_at => Some(
                std::fs::File::open(src)
                    .map_err(|e| fail(EXIT_CONFIG, format!("cannot read body file {src}: {e}")))?,
            ),
            _ => None,
        });
    }
    Ok(opened)
}

#[cfg(test)]
fn read_body_bounded(args: &CurlArgs, limit: usize) -> CliResult<Option<Vec<u8>>> {
    let sources = open_body_sources(args)?;
    read_body_with(args, limit, sources)
}

fn read_body_with(
    args: &CurlArgs,
    limit: usize,
    mut sources: Vec<Option<std::fs::File>>,
) -> CliResult<Option<Vec<u8>>> {
    let Some((pieces, reads_at, strip_newlines)) = body_pieces(args) else {
        return Ok(None);
    };

    let mut out: Vec<u8> = Vec::new();
    for (i, piece) in pieces.iter().enumerate() {
        if i > 0 {
            // curl's rule for repeated data options: the pieces are merged
            // with a separating `&`, which is what makes `-d a=1 -d b=2` a
            // form body rather than an error.
            //
            // Keyed on the piece INDEX, not on whether anything has been
            // written: an empty first piece (`-d '' -d action=delete`, or an
            // empty `@file`) still separates, so the body is `&action=delete`
            // the way curl sends it. A body that differs by a byte can
            // invalidate a signature or mean something else entirely.
            out.push(b'&');
        }
        let source = match piece.strip_prefix('@') {
            Some(src) if reads_at => src,
            _ => {
                out.extend_from_slice(piece.as_bytes());
                continue;
            }
        };
        // The bound is on the WHOLE body, so each piece may only use what is
        // left of it.
        let remaining = limit.saturating_sub(out.len());
        let mut buf = Vec::new();
        // The handle was opened by `open_body_sources`, before anything could
        // have created the file it names.
        match sources.get_mut(i).and_then(Option::take) {
            Some(file) => read_bounded(file, &mut buf, remaining)
                .map_err(|e| fail(EXIT_CONFIG, format!("cannot read body file {source}: {e}")))?,
            None => read_bounded(std::io::stdin().lock(), &mut buf, remaining)
                .map_err(|e| fail(EXIT_CONFIG, format!("cannot read the body from stdin: {e}")))?,
        }
        if strip_newlines {
            buf = strip_like_curl(&buf);
        }
        out.extend_from_slice(&buf);
    }
    // The per-piece bound governs each READ; it cannot govern the separators
    // or the inline pieces, which are argv and never went through
    // `read_bounded` at all. `-d @empty -d @empty -d @empty` under a 1-byte
    // bound assembles `&&` from three reads that each fitted. The bound is on
    // the whole body, so the whole body is what is finally measured — and with
    // the override set to mirror a deployment's proxy cap, this is the
    // difference between saying so now and spending an approval to be told in
    // a 413.
    if out.len() > limit {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "assembled request body is {} bytes, over the local {limit}-byte bound \
                 (raise it with {MAX_BODY_ENV} if this deployment allows more)",
                out.len()
            ),
        ));
    }
    Ok(Some(out))
}

/// Apply curl's `-d @file` stripping, which is not the "drop every CR and LF"
/// it is usually described as.
///
/// curl reads the file a line at a time and appends each line as a C STRING,
/// truncating it at the first `\r` it finds — so the bytes dropped are
/// everything from that point to the end of the line, not the one byte. A NUL
/// truncates for the same reason: the append never sees past it. Verified
/// against curl 8.5.0 through a recording server:
///
/// ```text
/// a\0b\r\nc  -> ac        a\rb\nc  -> ac       \0abc -> (empty)
/// a\nb\nc    -> abc       a\r\nb\r\nc -> abc   ab\0  -> ab
/// ```
///
/// Dropping the bytes individually instead would send `abc` where curl sends
/// `ac` — a different form body, and for a signed payload a different meaning.
/// `--data-binary` is curl's answer for input that must survive byte-exact,
/// and it is this function's absence rather than a variant of it.
fn strip_like_curl(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    for line in buf.split(|b| *b == b'\n') {
        let end = line
            .iter()
            .position(|b| *b == b'\r' || *b == b'\0')
            .unwrap_or(line.len());
        out.extend_from_slice(&line[..end]);
    }
    out
}

/// Read at most `limit` bytes, then stop: an unbounded read of a stuck producer
/// or a `@/dev/zero` slip would eat memory to no purpose. The message names the
/// override, because the bound is ours and the deployment's real cap may differ.
fn read_bounded(source: impl Read, buf: &mut Vec<u8>, limit: usize) -> std::io::Result<()> {
    // Saturating rather than wrapping: `max_body_bytes` already refuses a
    // limit with no room for the lookahead, and this is the other half of
    // that — a caller passing one directly gets a read that is merely
    // unbounded-in-practice, never one that reads zero bytes.
    source
        .take((limit as u64).saturating_add(1))
        .read_to_end(buf)?;
    if buf.len() > limit {
        buf.clear();
        return Err(std::io::Error::other(format!(
            "request body exceeds the local {limit}-byte read bound \
             (raise it with {MAX_BODY_ENV} if this deployment allows more)"
        )));
    }
    Ok(())
}

/// Map a Keychute-generated proxy error onto an exit code. Only ever called
/// for a response carrying [`KEYCHUTE_ERROR_HEADER`] — an upstream status of
/// the same number is the upstream's answer, not a refusal, and passes
/// through untouched.
fn classify_proxy_error(status: reqwest::StatusCode, body: &str) -> Failure {
    if status == reqwest::StatusCode::GONE {
        return classify_gone(body);
    }
    let msg = api_error_message(status, body);
    let code = match status.as_u16() {
        // Our own credential/config problem, not the upstream's.
        401 => EXIT_CONFIG,
        // A refusal by policy or by the grant's own constraints: the same
        // class of answer as a denied request, and equally not worth a retry.
        403 => EXIT_DENIED,
        // Malformed call, unusable path, oversize body: fix the invocation.
        400 | 405 | 413 => EXIT_CONFIG,
        _ => EXIT_OTHER,
    };
    fail(
        code,
        format!("brokered request rejected by Keychute: {msg}"),
    )
}

/// Derive the request idempotency key from the caller's key AND the exact call
/// this invocation would make.
///
/// The server's idempotency MAC deliberately excludes `context.structured`
/// (`api/canonical.rs`), and the query string is in no constraint — so with a
/// bare caller key, a rerun that changes only the query returns the ORIGINAL
/// approved request, and this command then proxies the NEW query under it. An
/// operator who approved `POST /transfer?to=trusted` would have that one
/// approval exercised as `POST /transfer?to=attacker`, with no second push and
/// nothing on any page showing the substitution.
///
/// Binding the call into the key makes "same key" mean "same call": an
/// identical rerun still resumes its original request (which is what
/// `--idempotency-key` is for — a command that died after approval but before
/// the proxy call), while a changed target mints a fresh request and a fresh
/// push carrying the new target.
///
/// "The call" is all of it, not just the target. The body and the forwarded
/// headers are in no constraint either, and neither is in `CreateAccessRequest`
/// at all — so a rerun that keeps the key and changes `-d` or a signed header
/// resumes the original approval and proxies the new bytes under it. A grant
/// with uses to spare may legitimately carry different bodies; a RESUMPTION
/// may not, because it claims to be the same call that was approved.
pub(crate) fn call_bound_idempotency_key(
    user_key: &str,
    method: &str,
    target: &Target,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Length-prefixed so no two different calls can produce the same preimage
    // by shifting a delimiter across fields.
    for field in [method, &target.origin.to_display(), &target.path] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    // A discriminator, not just the bytes: `/transfer` and `/transfer?` differ
    // in the request target actually sent, and an upstream is entitled to tell
    // them apart. Without this they hash alike, so the second run resumes the
    // first one's approval and proxies the other target under it.
    match &target.query {
        None => hasher.update([0u8]),
        Some(q) => {
            hasher.update([1u8]);
            hasher.update((q.len() as u64).to_be_bytes());
            hasher.update(q.as_bytes());
        }
    }
    // Headers in the order they will be sent: two invocations that send the
    // same fields in a different order are different requests, and an upstream
    // that signs over the header block can tell.
    hasher.update((headers.len() as u64).to_be_bytes());
    for (name, value) in headers {
        for field in [name.as_str(), value.as_str()] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
    }
    // Absent and empty are distinct here for the same reason `/x` and `/x?`
    // are: `-d ''` sends `Content-Length: 0`, no body at all sends nothing.
    match body {
        None => hasher.update([0u8]),
        Some(b) => {
            hasher.update([1u8]);
            hasher.update((b.len() as u64).to_be_bytes());
            hasher.update(b);
        }
    }
    let digest = hex::encode(hasher.finalize());
    format!("{user_key}-{}", &digest[..CALL_BINDING_HEX_CHARS])
}

/// Hex characters of SHA-256 kept in the derived key — 128 bits.
///
/// This is a collision bound, not a preimage one, and the party searching for
/// the collision is the same party choosing both queries: find two that hash
/// alike, get the benign one approved, then run the other under that approval.
/// At 64 bits that search is about 2^32 attempts — cheap enough for the exact
/// substitution this binding exists to prevent. 128 bits puts it at 2^64,
/// which is not.
const CALL_BINDING_HEX_CHARS: usize = 32;

/// The caller-key budget: the derived key appends `-` plus the hex above, and
/// the whole thing still has to fit the shared cap.
pub(crate) const MAX_CURL_USER_KEY_BYTES: usize = 124 - (CALL_BINDING_HEX_CHARS + 1);

/// Which credential this call authenticates with: a grant already approved,
/// or a secret to request one for.
enum Selector {
    Grant(Uuid),
    Secret(String),
}

/// Resolve the selector and validate its shape. Pure argument checking, so it
/// can run before anything is read or sent.
fn credential_selector(args: &CurlArgs) -> CliResult<Selector> {
    match &args.grant_id {
        Some(g) => {
            if args.secret.is_some() {
                eprintln!(
                    "keychute: --secret is ignored with --grant-id: the grant already names \
                     the credential the server will attach"
                );
            }
            let id = g
                .parse::<Uuid>()
                .map_err(|_| fail(EXIT_CONFIG, format!("invalid grant id {g:?}")))?;
            Ok(Selector::Grant(id))
        }
        None => args.secret.clone().map(Selector::Secret).ok_or_else(|| {
            fail(
                EXIT_CONFIG,
                "--secret <name> is required (or --grant-id to reuse an approved grant)",
            )
        }),
    }
}

/// Everything about the grant this invocation would ask for that can be
/// judged from arguments alone: the idempotency key's length, each
/// `--allow-method`, and whether the `--path-prefix` set covers the call.
///
/// Separate from [`constraints_for`], which builds the real object once the
/// method is known (it depends on whether a body was supplied). This runs
/// BEFORE the body is read, so `-d @-` cannot leave an already-invalid
/// invocation blocked on a producer, or swallow a finite one's input and only
/// then report the error. `constraints_for` re-runs the same rules rather than
/// trusting this to have happened.
fn validate_grant_options(args: &CurlArgs, target: &Target, method: &str) -> CliResult<()> {
    if let Some(key) = &args.idempotency_key {
        // `--idempotency-key ''` is an unset variable that expanded, not a
        // choice. It cannot reach the shared validator that would refuse it,
        // because `acquire_grant` appends the call hash first — so the key is
        // never empty by the time anything checks, and every identical call
        // derives the SAME key from the target alone. That silently resumes an
        // earlier approved request instead of pushing a new one.
        if key.is_empty() {
            return Err(fail(
                EXIT_CONFIG,
                "--idempotency-key is empty; omit it for a random key, or pass a real one",
            ));
        }
        if key.len() > MAX_CURL_USER_KEY_BYTES {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "--idempotency-key too long ({} bytes; max {MAX_CURL_USER_KEY_BYTES} here, \
                     because the call is bound into the key sent to the server)",
                    key.len()
                ),
            ));
        }
    }
    // A path with no canonical form is one the proxy refuses outright, so the
    // call cannot succeed however it is approved. Refusing it here rather than
    // deferring matters when an explicit `--path-prefix` is valid on its own:
    // the request would be accepted, a human would approve it, and only then
    // would the proxy reject the path. Saying so now costs nobody an approval.
    if canonical_path(&target.path).is_none() {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "the path {:?} is one the broker refuses: it must percent-decode once to valid \
                 UTF-8, with no encoded '/' or '\\', no '.' or '..' segment (judged before any \
                 ';'), no control characters and no '//'",
                target.path
            ),
        ));
    }
    // The server's own bounds (`requests.rs`), applied unconditionally there.
    // Mirrored rather than deferred for the same reason as everything else in
    // this function: each of these is decidable from the arguments, so a
    // `-d @-` invocation that is already certain to be rejected should not
    // first block on a producer that may never close.
    if args.ttl < 1 || args.ttl > MAX_TTL_SECONDS {
        return Err(fail(
            EXIT_CONFIG,
            format!("--ttl must be between 1 second and 30 days ({MAX_TTL_SECONDS} seconds)"),
        ));
    }
    if args.max_uses > MAX_SERVER_USES {
        return Err(fail(
            EXIT_CONFIG,
            format!("--max-uses must be at most {MAX_SERVER_USES} (0 means no cap)"),
        ));
    }
    // `Duration::from_secs_f64` PANICS on a negative, NaN or overflowing
    // value, so the range is checked rather than trusted to clap, which only
    // knows the argument parses as a float.
    if !(args.max_time.is_finite()
        && args.max_time >= 0.0
        && args.max_time <= MAX_APPROVAL_WAIT_SECONDS as f64)
    {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "--max-time must be between 0 (no limit) and {MAX_APPROVAL_WAIT_SECONDS} seconds"
            ),
        ));
    }
    if args.timeout > MAX_APPROVAL_WAIT_SECONDS {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "--timeout must be at most {MAX_APPROVAL_WAIT_SECONDS} seconds (30 days), \
                 which already outlives the longest grant"
            ),
        ));
    }
    // Only when the name is going to be USED. `--grant-id` reuses a grant that
    // already names the credential, and `credential_selector` says so plainly;
    // rejecting the call over the length of an argument just reported to have
    // no effect would contradict that message for no gain.
    if let Some(name) = args.secret.as_ref().filter(|_| args.grant_id.is_none()) {
        if name.is_empty() || name.len() > MAX_SECRET_NAME_BYTES {
            return Err(fail(
                EXIT_CONFIG,
                format!("--secret must be 1 to {MAX_SECRET_NAME_BYTES} bytes"),
            ));
        }
    }
    if args.reason.len() > MAX_REASON_BYTES {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "--reason too long ({} bytes; max {MAX_REASON_BYTES})",
                args.reason.len()
            ),
        ));
    }
    // Each list the server bounds. Methods are counted the way
    // `constraints_for` builds them: normalized, deduplicated, and led by the
    // call's OWN method — which is why that method is passed in rather than
    // guessed. It is decidable without reading anything: `-X` names it, and
    // failing that the mere PRESENCE of a data argument makes it POST. A count
    // that omitted it would accept exactly the case the server then rejects,
    // 32 `--allow-method` values that do not include the inferred one.
    let mut distinct: Vec<String> = vec![method.to_string()];
    for m in &args.allow_methods {
        let m = normalize_method(m).map_err(|e| fail(EXIT_CONFIG, e))?;
        if !distinct.contains(&m) {
            distinct.push(m);
        }
    }
    if distinct.len() > MAX_CONSTRAINT_ENTRIES {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "too many distinct methods ({}, counting {method} for the call itself; the \
                 server accepts at most {MAX_CONSTRAINT_ENTRIES} per constraint list)",
                distinct.len()
            ),
        ));
    }
    if args.path_prefixes.len() > MAX_CONSTRAINT_ENTRIES {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "too many --path-prefix values ({}; the server accepts at most \
                 {MAX_CONSTRAINT_ENTRIES} per constraint list)",
                args.path_prefixes.len()
            ),
        ));
    }
    // Reuses the real rule so the two cannot drift.
    if !args.path_prefixes.is_empty() {
        constraints_for(
            target,
            method,
            &[],
            &args.path_prefixes,
            args.ttl,
            args.max_uses,
        )
        .map_err(|e| fail(EXIT_CONFIG, e))?;
    }
    Ok(())
}

/// Build the agent-asserted context for the access request, and prove it fits.
///
/// The grant block the server parses out of the constraints is what the
/// approval page presents as fact, but the full target — query string included
/// — is what the operator actually reads, and it is forwarded verbatim, so it
/// belongs in front of them.
///
/// The shedding runs after the target is inserted, not just at build time: the
/// target is MANDATORY and the capture is a courtesy, so a capture that fitted
/// on its own must not be what pushes the target past the server's cap.
///
/// And then the result is measured. Shedding can only drop capture sections;
/// a target whose own displayed URL exceeds the cap — a ~17 KiB query is well
/// within argv limits — leaves a map nothing can shrink, which the server
/// rejects outright. Deciding that here is what keeps `-d @-` from blocking on
/// a producer for a request already certain to be refused.
fn build_request_context(target: &Target, method: &str) -> CliResult<serde_json::Value> {
    let mut structured = build_structured_context().unwrap_or(serde_json::json!({}));
    if let Some(map) = structured.as_object_mut() {
        map.insert(
            "target".to_string(),
            serde_json::Value::String(format!("{method} {}", target.display())),
        );
        crate::shed_structured_to_fit(map);
        let len = serde_json::to_vec(map).map(|v| v.len()).unwrap_or(0);
        if len > crate::MAX_STRUCTURED_BYTES {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "the approval context is {len} bytes, over the server's \
                     {}-byte limit, and nothing left in it can be dropped — the target \
                     itself is too long. Shorten the URL (its query string is the usual \
                     culprit) or move the detail into --reason.",
                    crate::MAX_STRUCTURED_BYTES
                ),
            ));
        }
    }
    Ok(structured)
}

/// Open `--output` before any approval is asked for, and KEEP the handle.
///
/// A destination that cannot be opened is a local failure the operator should
/// never be woken for: the approval would be spent and the grant stranded —
/// with the default `--max-uses 1` there is not even a grant id printed to
/// retry with. Inspecting the path cannot establish this. A directory, a
/// missing parent, a dangling symlink and a file the caller may not write all
/// look different to `is_dir`/`exists` and identical to `open`, so the only
/// honest test is the open itself.
///
/// `create` without `truncate`: an existing file must survive an approval wait
/// that may end in a denial, so it is emptied in `proxy_call` at the moment
/// there is a response to put there. A destination that did not exist is
/// created empty now, as curl also does.
///
/// `None` means stdout — either no `--output` or curl's `-o -` spelling for
/// it. Treating `-` as a filename would create a file literally called `-` and
/// leave stdout empty on a call that succeeded.
fn open_output(args: &CurlArgs) -> CliResult<Option<std::fs::File>> {
    let Some(path) = &args.output else {
        return Ok(None);
    };
    if path.as_os_str() == "-" {
        return Ok(None);
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map(Some)
        .map_err(|e| {
            fail(
                EXIT_CONFIG,
                format!("cannot write --output {}: {e}", path.display()),
            )
        })
}

/// Refuse `--output` naming the file the CLI's own bearer token is read from.
///
/// `Config::bearer` re-reads that file on every call, and `proxy_call`
/// truncates the output file at the last moment — deliberately, so an existing
/// file survives the approval wait. Together those two make `-o $KEYCHUTE_TOKEN_FILE`
/// destroy the credential BETWEEN the approval and the call that needed it:
/// the request is created and approved with a token that still exists, the
/// truncate empties the file, and the bearer read a few lines later fails. The
/// grant is stranded, and the CLI has no credential left to look it up with or
/// to make any other call — including the one that would write the token back.
///
/// Checked here rather than at open time because by then the damage is the
/// thing being prevented, and because a preflight refusal costs no approval.
fn refuse_output_over_token_file(cfg: &Config, args: &CurlArgs) -> CliResult<()> {
    let (Some(out), Some(token_file)) = (args.output.as_ref(), cfg.token_file.as_ref()) else {
        return Ok(());
    };
    if out.as_os_str() == "-" {
        return Ok(());
    }
    if !same_file(out, token_file) {
        return Ok(());
    }
    Err(fail(
        EXIT_CONFIG,
        format!(
            "refusing --output {}: that is KEYCHUTE_TOKEN_FILE, and the response would \
             overwrite the token this CLI authenticates with — after the approval was \
             spent and before the call could use it. Write the body somewhere else.",
            out.display()
        ),
    ))
}

/// Whether two paths name the same file.
///
/// Identity first, spelling second. A hard link gives the same inode two
/// unrelated pathnames, so no amount of path resolution relates them — and
/// truncating either one empties the token, since it is the inode `set_len(0)`
/// acts on. Both existing files are therefore compared by (device, inode).
///
/// Only when the output does not exist yet does this fall back to comparing
/// resolved paths: nothing has been created to have an identity, and the
/// resolution still catches symlinks, `.` and `..` in the spelling.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return (ma.dev(), ma.ino()) == (mb.dev(), mb.ino());
        }
    }
    fn resolve(p: &std::path::Path) -> std::path::PathBuf {
        if let Ok(c) = std::fs::canonicalize(p) {
            return c;
        }
        match (p.parent(), p.file_name()) {
            (Some(dir), Some(name)) => match std::fs::canonicalize(dir) {
                Ok(d) => d.join(name),
                Err(_) => p.to_path_buf(),
            },
            _ => p.to_path_buf(),
        }
    }
    resolve(a) == resolve(b)
}

pub(crate) async fn run_curl(
    cfg: &Config,
    http: &reqwest::Client,
    args: CurlArgs,
) -> CliResult<()> {
    let target = parse_target(&args.url).map_err(|e| fail(EXIT_CONFIG, e))?;

    // Settle EVERY body-independent usage question before reading the body.
    // `-d @-` consumes stdin, so anything checked afterwards means an
    // invocation already known to be invalid still blocks on a producer that
    // may never close — or, with a finite one, swallows its input and only
    // then reports the error. Selector, method and headers all qualify.
    let selector = credential_selector(&args)?;
    refuse_output_over_token_file(cfg, &args)?;
    // Read once here purely to settle whether it CAN be read. Local
    // authentication that is already certain to fail is a config error like
    // any other, and `-d @-` means a check deferred past the body read blocks
    // on a producer for an invocation that cannot succeed. The value is
    // discarded: every later call re-reads the file, so rotation mid-flight
    // still works.
    cfg.bearer()?;
    // Decidable without reading a byte of it: curl's rule is that a body
    // implies POST, and whether there will BE a body is settled by the mere
    // presence of a data argument. Inferring it here rather than after
    // `read_body` is what lets the method take part in the checks below.
    let method = match &args.method {
        Some(m) => normalize_method(m).map_err(|e| fail(EXIT_CONFIG, e))?,
        None if body_is_supplied(&args) => "POST".to_string(),
        None => "GET".to_string(),
    };
    let mut parsed = Vec::new();
    // `Name:` removals. Most name a header nothing here would have sent, and
    // curl treats those as the no-ops they are — but `User-Agent` is one this
    // CLI sets itself, so a removal of it has to survive as an instruction
    // rather than just an absence.
    let mut suppress_user_agent = false;
    for line in &args.headers {
        match parse_header(line).map_err(|e| fail(EXIT_CONFIG, e))? {
            Some(h) => parsed.push(h),
            None => {
                let name = line
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if name == "user-agent" {
                    suppress_user_agent = true;
                }
            }
        }
    }
    validate_grant_options(&args, &target, &method)?;
    // The last body-independent question, and the only one that needs the
    // network: whether a reused grant covers this call at all. Its mechanism,
    // origin, method and path are properties of the GRANT, so an invocation
    // certain to be refused should not first block on a producer.
    //
    // The fresh-grant path is the other way round on purpose — `acquire_grant`
    // waits for a human, and asking for that before the body is in hand would
    // spend the approval on a call that might still fail to assemble.
    let structured = match &selector {
        Selector::Grant(id) => {
            check_grant_covers(cfg, http, *id, &target, &method).await?;
            None
        }
        Selector::Secret(_) => Some(build_request_context(&target, &method)?),
    };
    // Inputs before outputs, so `-d @payload -o payload` cannot answer its own
    // missing file with an empty one.
    let sources = open_body_sources(&args)?;
    let output = open_output(&args)?;

    let body = read_body_with(&args, max_body_bytes()?, sources)?;
    // A `Connection: X-Internal` header nominates X-Internal as hop-by-hop,
    // and the broker honours that — but only if it can still SEE the
    // Connection header. Since `Connection` is itself on the strip list, a
    // naive drop would leave X-Internal looking like an ordinary header and
    // forward it upstream, which is not what the same headers sent straight
    // at the proxy would do. So the nomination is resolved here, before its
    // evidence is discarded.
    let nominated = connection_nominated(&parsed);
    let mut headers = Vec::new();
    for (name, value) in parsed {
        if is_stripped_header(&name) {
            eprintln!(
                "keychute: header {name:?} is not forwarded by the broker (it would let the \
                 caller redirect or re-authenticate the credentialed request); dropping it"
            );
            continue;
        }
        if nominated.contains(&name) {
            eprintln!(
                "keychute: header {name:?} is named by your Connection header, so it is \
                 hop-by-hop and not forwarded; dropping it"
            );
            continue;
        }
        headers.push((name, value));
    }

    let (grant_id, freshly_approved) = match selector {
        // Already validated, above.
        Selector::Grant(id) => (id, false),
        Selector::Secret(secret_name) => (
            acquire_grant(
                cfg,
                http,
                &args,
                &target,
                &method,
                secret_name,
                structured.expect("a secret selector builds its context"),
                &headers,
                body.as_deref(),
            )
            .await?,
            true,
        ),
    };

    // A `User-Agent:` removal cannot be expressed on a client that has a
    // default one — reqwest fills the default into any request without the
    // header — so the removal is honoured by using a client that has none.
    let ua_free;
    let proxy_http = if suppress_user_agent {
        ua_free = crate::build_http_client_with(cfg, None)?;
        &ua_free
    } else {
        http
    };
    let result = proxy_call(
        cfg, proxy_http, &args, &target, &method, headers, body, grant_id, output,
    )
    .await;
    // AFTER the call, deliberately. The grant's clock starts at approval, and
    // this lookup is a diagnostic: letting it run first means a slow or lost
    // response can spend a short TTL before the call it was approved for ever
    // goes out, turning a best-effort courtesy into an expired grant. Still
    // printed when the call failed — a grant with uses left is exactly what
    // someone retrying wants to know about.
    //
    // A FAILED call reports even under the default `--max-uses 1`, which is the
    // one case where the ID is otherwise never printed. A failure before the
    // proxy accounted the use — the connection to Keychute dropping between
    // approval and the request — leaves the single use unspent, and the default
    // idempotency key is random, so re-running asks a human to approve the same
    // thing again instead of reusing what they just granted. The lookup decides
    // which it was; `report_reuse_budget` prints "spent" when it was spent.
    if freshly_approved && (args.max_uses != 1 || result.is_err()) {
        report_reuse_budget(cfg, http, &args, grant_id).await;
    }
    result
}

/// Whether a body will be read, decidable from the arguments alone. Only the
/// presence of a data argument matters, not what it says: `-d @-` supplies a
/// body whatever ends up on stdin, empty included.
fn body_is_supplied(args: &CurlArgs) -> bool {
    !args.data.is_empty() || !args.data_raw.is_empty() || !args.data_binary.is_empty()
}

/// Fetch a grant's metadata (never any credential material).
async fn fetch_grant(cfg: &Config, http: &reqwest::Client, grant_id: Uuid) -> CliResult<GrantInfo> {
    let resp = http
        .get(format!("{}/v1/grants/{}", cfg.url, grant_id))
        .bearer_auth(cfg.bearer()?)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| fail(EXIT_OTHER, format!("grant lookup failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| fail(EXIT_OTHER, format!("failed reading grant lookup: {e}")))?;
    if !status.is_success() {
        let code = match status.as_u16() {
            401 => EXIT_CONFIG,
            // 404 covers "no such grant" AND "someone else's grant" — the
            // server does not distinguish, and neither should the message.
            403 | 404 => EXIT_CONFIG,
            _ => EXIT_OTHER,
        };
        return Err(fail(
            code,
            format!(
                "grant {grant_id} lookup failed: {}",
                api_error_message(status, &text)
            ),
        ));
    }
    serde_json::from_str(&text)
        .map_err(|e| fail(EXIT_OTHER, format!("unexpected grant lookup response: {e}")))
}

/// Refuse to exercise a reused grant that does not cover this call.
///
/// The origin check is the load-bearing one. The proxy takes the upstream
/// origin from the GRANT, never from the URL passed here — so without this, a
/// `--grant-id` pointing at a grant for `api.example.com` combined with a URL
/// naming `other.example` would deliver the request to `api.example.com` while
/// every diagnostic printed `other.example`. For a POST or DELETE that is a
/// side effect landing on the wrong service, invisibly. Local refusal is the
/// only place this can be caught: server-side, the call is perfectly valid.
///
/// Method and path are checked too — the server would refuse them with a 403,
/// but finding out before the request leaves is strictly better, and the
/// message can say which constraint failed instead of "not allowed by grant".
async fn check_grant_covers(
    cfg: &Config,
    http: &reqwest::Client,
    grant_id: Uuid,
    target: &Target,
    method: &str,
) -> CliResult<()> {
    let info = fetch_grant(cfg, http, grant_id).await?;
    if info.mechanism != Mechanism::Brokered {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "grant {grant_id} is a {} grant, not a brokered one: it releases a secret \
                 rather than proxying a request (see `keychute request`)",
                info.mechanism.as_str()
            ),
        ));
    }
    // Revoked, expired, exhausted: three ways for `begin_grant_use` to refuse
    // this grant on facts already in hand. Checking only the first left the
    // other two to be discovered after `-d @-` had consumed stdin, for a call
    // whose outcome was never in doubt.
    //
    // The server remains the authority — its clock and its use count are the
    // ones that decide, and a grant that passes here can still be refused
    // there. This only declines to read a body for a grant that cannot
    // possibly work.
    if info.revoked {
        return Err(fail(
            crate::EXIT_TIMEOUT,
            format!("grant {grant_id} has been revoked; request a new one"),
        ));
    }
    if info.not_after <= chrono::Utc::now() {
        return Err(fail(
            crate::EXIT_TIMEOUT,
            format!(
                "grant {grant_id} expired at {}; request a new one",
                info.not_after.to_rfc3339()
            ),
        ));
    }
    if let Some(max) = info.max_uses {
        if info.use_count >= max {
            return Err(fail(
                EXIT_OTHER,
                format!(
                    "grant {grant_id} is exhausted ({}/{max} uses); request a new one",
                    info.use_count
                ),
            ));
        }
    }
    match info.constraints.origins.as_slice() {
        [approved] if approved.same_target(&target.origin) => {}
        [approved] => {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "grant {grant_id} was approved for {}, but this URL targets {}. \
                     The proxy sends to the APPROVED origin regardless of the URL, so this \
                     would have gone to {} — request a new grant for {}",
                    approved.to_display(),
                    target.origin.to_display(),
                    approved.to_display(),
                    target.origin.to_display(),
                ),
            ))
        }
        _ => {
            return Err(fail(
                EXIT_OTHER,
                format!("grant {grant_id} does not name exactly one origin"),
            ))
        }
    }
    if !info.constraints.methods.is_empty()
        && !info
            .constraints
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "grant {grant_id} covers {} but this call is {method}",
                info.constraints.methods.join(", ")
            ),
        ));
    }
    // Compare canonical against canonical: the grant holds the decoded prefix
    // and the URL holds the raw path. A path the server would reject outright
    // has no canonical form — leave that answer to the server rather than
    // inventing a local one.
    if let Some(canonical) = canonical_path(&target.path) {
        if !info.constraints.path_prefixes.is_empty()
            && !info
                .constraints
                .path_prefixes
                .iter()
                .any(|p| path_covered(p, &canonical))
        {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "grant {grant_id} covers {} but this call is for {canonical}",
                    info.constraints.path_prefixes.join(", "),
                ),
            ));
        }
    }
    Ok(())
}

/// Percent-decode a path once, the way the server canonicalizes before it
/// stores a prefix or matches a request (`policy::paths::canonicalize`).
///
/// Returns None when the server would reject the path outright (encoded `/`
/// or `\\`, a truncated or invalid escape, non-UTF-8) — the caller then skips
/// the local check rather than guessing, and lets the server give its own
/// answer.
///
/// This matters because the two sides hold different spellings: a grant made
/// for `/files/a%20b` stores the canonical `/files/a b`, while the URL a
/// reuse is given still reads `/files/a%20b`. Comparing those raw would refuse
/// the identical call the grant was made for.
pub(crate) fn canonical_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 3 > bytes.len() {
                    return None;
                }
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                let v = (hex(bytes[i + 1])? << 4) | hex(bytes[i + 2])?;
                // The server rejects these rather than decoding them.
                if v == b'/' || v == b'\\' {
                    return None;
                }
                out.push(v);
                i += 3;
            }
            b'\\' => return None,
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    let decoded = String::from_utf8(out).ok()?;
    // Everything below mirrors `server/src/policy/paths.rs::canonicalize`, which
    // rejects rather than resolves. A path it refuses has no canonical form
    // here either, so the local checks skip it and the server gives the answer.
    // Getting this wrong is not merely a missed diagnostic: judging such a path
    // "covered" spends a human approval on a call the proxy then refuses.
    if decoded.chars().any(|c| c.is_control()) {
        return None;
    }
    // Dot segments are judged by the portion BEFORE any `;`, because
    // servlet-family upstreams strip `;params` and only then normalize — so
    // `..;x` lands on `..` upstream and escapes the approved prefix.
    if decoded.split('/').any(|seg| {
        let base = seg.split(';').next().unwrap_or(seg);
        base == "." || base == ".."
    }) {
        return None;
    }
    if decoded.contains("//") {
        return None;
    }
    Some(decoded)
}

/// Prefix match at `/` segment boundaries, mirroring the server's rule:
/// `/v1/account` covers `/v1/account` and `/v1/account/…`, never
/// `/v1/account-delete`.
///
/// Both arguments must already be canonical — see [`canonical_path`].
pub(crate) fn path_covered(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// Ask for — and wait on — a grant that permits exactly this call.
// Same shape as `proxy_call` below, and for the same reason: the arguments ARE
// the call, and bundling them into a struct only moves the list.
#[allow(clippy::too_many_arguments)]
async fn acquire_grant(
    cfg: &Config,
    http: &reqwest::Client,
    args: &CurlArgs,
    target: &Target,
    method: &str,
    secret_name: String,
    structured: serde_json::Value,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> CliResult<Uuid> {
    let user_key = args
        .idempotency_key
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    // Re-checked here rather than assumed: `validate_grant_options` runs it
    // earlier so the failure lands before stdin is read, but this is the call
    // site that depends on it holding.
    if user_key.len() > MAX_CURL_USER_KEY_BYTES {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "--idempotency-key too long ({} bytes; max {MAX_CURL_USER_KEY_BYTES} here, \
                 because the call is bound into the key sent to the server)",
                user_key.len()
            ),
        ));
    }
    let idem_key = call_bound_idempotency_key(&user_key, method, target, headers, body);
    validate_idempotency_key(&idem_key).map_err(|e| fail(EXIT_CONFIG, e))?;
    let constraints = constraints_for(
        target,
        method,
        &args.allow_methods,
        &args.path_prefixes,
        args.ttl,
        args.max_uses,
    )
    .map_err(|e| fail(EXIT_CONFIG, e))?;

    let body = CreateAccessRequest {
        idempotency_key: idem_key.clone(),
        secret_name,
        mechanism: Mechanism::Brokered,
        constraints,
        context: RequestContext {
            reason: args.reason.clone(),
            structured: Some(structured),
        },
    };

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut st = create_access_request(cfg, http, &body).await?;
    if st.state == RequestState::Pending {
        eprintln!(
            "Waiting for approval: {}/ui/requests/{}",
            cfg.external_url, st.request_id
        );
        st = wait_for_resolution(cfg, http, st.request_id, deadline).await?;
    }
    match st.state {
        RequestState::Approved => {}
        RequestState::Denied => {
            let why = st
                .deny_reason
                .filter(|r| !r.is_empty())
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            return Err(fail(EXIT_DENIED, format!("request denied{why}")));
        }
        RequestState::Expired => {
            return Err(fail(crate::EXIT_TIMEOUT, "request expired before approval"))
        }
        RequestState::Pending => {
            return Err(fail(
                crate::EXIT_TIMEOUT,
                format!("timed out after {}s waiting for approval", args.timeout),
            ))
        }
    }
    let grant_id = st.grant_id.ok_or_else(|| {
        fail(
            EXIT_OTHER,
            "server reported approval but returned no grant id",
        )
    })?;
    Ok(grant_id)
}

/// Say whether a freshly approved grant can serve a SECOND call.
///
/// That is a property of what was GRANTED, not of what was asked for: the
/// approval form lets the operator narrow `max_uses` and `ttl_seconds`, so a
/// request for 5 uses may well have been approved for 1 — and promising reuse
/// then would send the caller after a grant that is already spent. Only the
/// server knows, hence the lookup.
///
/// Best-effort in both directions: it prints, it never fails, and it runs
/// after the call it describes so it cannot delay one.
async fn report_reuse_budget(
    cfg: &Config,
    http: &reqwest::Client,
    args: &CurlArgs,
    grant_id: Uuid,
) {
    match fetch_grant(cfg, http, grant_id).await {
        Ok(info) => {
            let remaining = info
                .max_uses
                .map(|max| max.saturating_sub(info.use_count))
                // No cap: bounded by the TTL alone.
                .unwrap_or(u32::MAX);
            // Uses left is not the same as usable. The grant can be revoked
            // while the call it was approved for is in flight, and a short TTL
            // can run out during a slow one — `not_after` is measured from
            // APPROVAL, not from now. Printing "good for 4 more calls, no
            // second approval" for either would send someone after a grant
            // that answers `grant-expired`.
            let spent = info.revoked || info.not_after <= chrono::Utc::now();
            if remaining > 0 && !spent {
                let budget = match info.max_uses {
                    Some(_) => format!("{remaining} more call(s)"),
                    None => "further calls".to_string(),
                };
                eprintln!(
                    "keychute: grant {grant_id} approved until {} — good for {budget}; \
                     reuse it with `--grant-id {grant_id}` (no second approval)",
                    info.not_after.to_rfc3339()
                );
            } else if info.revoked {
                eprintln!("keychute: grant {grant_id} has been revoked; it cannot be reused");
            } else if spent {
                eprintln!(
                    "keychute: grant {grant_id} expired at {} — its TTL ran out during this \
                     call, so there is nothing left to reuse",
                    info.not_after.to_rfc3339()
                );
            } else {
                // Reachable under `--max-uses 1` now that a failed call reports
                // too, so the "narrowed from" clause has to be conditional —
                // "narrowed from the 1 requested" would describe a narrowing
                // that never happened.
                let narrowed = if args.max_uses == 1 {
                    String::new()
                } else {
                    format!(" (narrowed from the {} requested)", args.max_uses)
                };
                eprintln!(
                    "keychute: grant {grant_id} was approved for a single use{narrowed}, \
                     and this call spent it"
                );
            }
        }
        Err(e) => eprintln!(
            "keychute: could not read back the granted limits: {}",
            e.message
        ),
    }
}

/// Make the proxied call and stream the upstream's answer out.
///
/// Deliberately a single attempt: this is the caller's HTTP request with
/// whatever side effects it has, and a retry would repeat them. It is also
/// use-accounted server-side, so a blind retry can burn the grant.
#[allow(clippy::too_many_arguments)]
async fn proxy_call(
    cfg: &Config,
    http: &reqwest::Client,
    args: &CurlArgs,
    target: &Target,
    method: &str,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    grant_id: Uuid,
    output: Option<std::fs::File>,
) -> CliResult<()> {
    // The destination was OPENED by `open_output`, before the approval — a
    // request that has already been delivered cannot be un-delivered, and
    // reporting "cannot open /nope/out.json" after a POST has committed
    // upstream invites a retry that repeats the side effect.
    //
    // Emptying it is deferred to here, the last moment before anything leaves:
    // an existing file must survive an approval wait that ends in a denial.
    // Truncating one we then fail to fill is the lesser harm, and is what curl
    // does too.
    // `open_output` returns no file for stdout — either no `--output` or
    // curl's `-o -` spelling for it.
    let to_stdout = output.is_none();
    let mut sink: Box<dyn Write> = match output {
        None => Box::new(std::io::stdout().lock()),
        Some(file) => {
            file.set_len(0).map_err(|e| {
                fail(
                    EXIT_CONFIG,
                    format!(
                        "cannot write --output {}: {e}",
                        args.output.as_ref().expect("a file means a path").display()
                    ),
                )
            })?;
            Box::new(file)
        }
    };

    // The path goes on RAW: the server canonicalizes it and rejects ambiguous
    // encodings, which only works if the encoding survives the trip.
    let mut url = format!("{}/v1/grants/{}/proxy{}", cfg.url, grant_id, target.path);
    if let Some(q) = &target.query {
        url.push('?');
        url.push_str(q);
    }
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| fail(EXIT_CONFIG, "invalid HTTP method"))?;
    let mut req = http
        .request(method.clone(), &url)
        .bearer_auth(cfg.bearer()?);
    // curl reads --max-time 0 as "no limit"; passing it to reqwest verbatim
    // would instead time out instantly — and a request that was already sent
    // can still commit upstream, so the caller would be told it failed and
    // invited to repeat a side effect that succeeded.
    if args.max_time > 0.0 {
        req = req.timeout(Duration::from_secs_f64(args.max_time));
    }
    for (name, value) in headers {
        req = req.header(name, value);
    }
    if let Some(b) = body {
        req = req.body(b);
    }
    let mut resp = req.send().await.map_err(|e| {
        fail(
            EXIT_OTHER,
            format!("brokered request to {} failed: {e}", target.display()),
        )
    })?;

    let status = resp.status();
    let from_keychute = resp.headers().contains_key(KEYCHUTE_ERROR_HEADER);
    if from_keychute {
        let text = resp.text().await.unwrap_or_default();
        return Err(classify_proxy_error(status, &text));
    }

    // Everything from here is the UPSTREAM's answer: its status is data, not a
    // failure of ours. `--fail` is the opt-in that turns it into one.
    // `>= 400`, not "4xx or 5xx". curl's rule is the numeric one, and an
    // upstream is free to answer 600: `is_client_error`/`is_server_error` are
    // both false there, so class-based checks would quietly hand a documented
    // failure back as a success with its body printed.
    //
    // Decided here but ACTED ON below the header block: curl has printed the
    // headers of a failing response under `-i -f` since 7.75.0, and 8.5.0 does
    // (`curl -sfi` against a 404 writes the status line and headers, no body,
    // exit 22). `--fail` suppresses the body, not the record of what came back.
    let failed = args.fail && status.as_u16() >= 400;
    if status.is_redirection() {
        // Neither side follows redirects: the credential must not be replayed
        // at a location nobody approved. Say so, since curl users expect -L
        // to be an option here and it deliberately is not.
        eprintln!(
            "keychute: upstream returned {status} — redirects are never followed \
             (the credential would go to an unapproved origin). Re-run against the \
             Location target if it is one you want approved."
        );
    }

    if args.include {
        // Byte-faithful: header values may carry obs-text (a legacy
        // Set-Cookie with a 0xff in it), which `HeaderValue` and the proxy
        // both pass through intact. Rendering them through a lossy UTF-8
        // conversion would silently substitute replacement characters into
        // output whose whole purpose is to show what actually arrived.
        // The version is a fixed placeholder ON PURPOSE. These headers are the
        // UPSTREAM's, relayed by the proxy; the upstream's negotiated protocol
        // is not carried across and this process never spoke to it. The only
        // version available here is the CLI's own connection to Keychute, which
        // describes a different hop entirely — printing it would state
        // something false about the response being shown.
        let mut head: Vec<u8> = format!("HTTP/1.1 {status}\r\n").into_bytes();
        for (name, value) in resp.headers() {
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        write_all(&mut sink, &head)?;
    }
    // The body, and only the body, is what `--fail` withholds. Flushed first
    // because the return abandons the sink, and a buffered `--output` file
    // would otherwise keep the headers that were just written to it.
    if failed {
        sink.flush()
            .map_err(|e| fail(EXIT_OTHER, format!("failed flushing the response: {e}")))?;
        return Err(fail(
            EXIT_OTHER,
            format!(
                "{} {} returned {} (--fail)",
                method,
                target.display(),
                status
            ),
        ));
    }
    // Tracked so the newline below is added only when the output actually
    // needs one — see there.
    let mut last_byte: Option<u8> = None;
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        fail(
            EXIT_OTHER,
            format!("reading the upstream response failed: {e}"),
        )
    })? {
        if let Some(b) = chunk.last() {
            last_byte = Some(*b);
        }
        write_all(&mut sink, &chunk)?;
    }
    sink.flush()
        .map_err(|e| fail(EXIT_OTHER, format!("failed flushing the response: {e}")))?;
    // A body that does not end in a newline would run into the shell prompt,
    // so on a terminal one is added — but ONLY then. A body that already ends
    // in `\n` would otherwise gain a visible blank line, and an empty body
    // would gain a line of its own. Pipes get the bytes verbatim either way.
    if to_stdout && std::io::stdout().is_terminal() && matches!(last_byte, Some(b) if b != b'\n') {
        let _ = std::io::stdout().lock().write_all(b"\n");
    }
    eprintln!("keychute: {} {} -> {}", method, target.display(), status);
    Ok(())
}

fn write_all(sink: &mut Box<dyn Write>, bytes: &[u8]) -> CliResult<()> {
    sink.write_all(bytes)
        .map_err(|e| fail(EXIT_OTHER, format!("failed writing the response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing_keeps_the_raw_path_and_query() {
        let t = parse_target("https://api.example.com/v1/things?limit=10&q=a%20b").unwrap();
        assert_eq!(t.origin.host, "api.example.com");
        assert_eq!(t.origin.port, None);
        assert_eq!(t.path, "/v1/things");
        assert_eq!(t.query.as_deref(), Some("limit=10&q=a%20b"));
        // Encoded separators survive to the server, which is what rejects them.
        let t = parse_target("https://api.example.com/v1%2Fthings").unwrap();
        assert_eq!(t.path, "/v1%2Fthings");
        // A bare origin still yields a path.
        assert_eq!(parse_target("https://api.example.com").unwrap().path, "/");
        // Non-default port becomes part of the origin.
        let t = parse_target("https://api.example.com:8443/v1").unwrap();
        assert_eq!(t.origin.port, Some(8443));
        // 443 spelled out is the default port and normalizes away, so the
        // approved origin reads the same either way.
        assert_eq!(
            parse_target("https://api.example.com:443/v1")
                .unwrap()
                .origin
                .port,
            None
        );
        // A noncanonical numeric host is normalized by the URL parser BEFORE
        // it becomes an origin, so the operator approves the host the request
        // will actually reach — not the spelling that was typed.
        assert_eq!(
            parse_target("https://2130706433/v1").unwrap().origin.host,
            "127.0.0.1"
        );
    }

    #[test]
    fn target_parsing_refuses_what_would_mislead_the_approver() {
        // Plaintext: the credential would leave Keychute unencrypted.
        assert!(parse_target("http://api.example.com/v1").is_err());
        // Userinfo: reads as one host, targets another.
        assert!(parse_target("https://api.example.com@attacker.example/v1").is_err());
        // Schemes with no proxy leg at all.
        assert!(parse_target("ftp://api.example.com/v1").is_err());
        assert!(parse_target("not a url").is_err());
        // Hosts Origin::parse refuses, for its own reasons.
        assert!(parse_target("https://*.example.com/v1").is_err());
        // Tab, CR and LF are DELETED by the URL parser, not rejected — so the
        // target displayed to the operator would not be the target sent.
        assert!(parse_target("https://api.example.com/v1?amount=1\n000").is_err());
        assert!(parse_target("https://api.example.com/v1\t/x").is_err());
        assert!(parse_target("https://api.example.com/v1?a=1\r").is_err());
        // The rest of the C0 controls are deleted at the ENDS instead, which
        // the approval text and the call binding would still have carried.
        assert!(parse_target("https://api.example.com/v1?to=alice\u{0}").is_err());
        assert!(parse_target("\u{1}https://api.example.com/v1").is_err());
        assert!(parse_target("https://api.example.com/v1?a=1\u{7f}").is_err());
        // Spaces at either end are trimmed the same way — and one in the
        // MIDDLE is kept but re-spelled: `raw_path_and_query` hands the
        // approval text and the call binding `account=a b`, while `proxy_call`
        // re-parses the assembled URL and sends `account=a%20b`. curl 8.5.0
        // refuses all three as a malformed URL rather than encoding for you.
        assert!(parse_target("https://api.example.com/v1?a=1 ").is_err());
        assert!(parse_target(" https://api.example.com/v1").is_err());
        assert!(parse_target("https://api.example.com/v1?account=a b").is_err());
        assert!(parse_target("https://api.example.com/a b").is_err());
        // Same divergence, other characters: the parser re-spells these too.
        assert!(parse_target("https://api.example.com/v1?q=\"x\"").is_err());
        assert!(parse_target("https://api.example.com/caf\u{e9}").is_err());
        assert!(parse_target("https://api.example.com/v1?a=\u{e9}").is_err());
        assert!(parse_target("https://api.example.com/v1/a<b").is_err());
        // Characters it passes through are NOT refused: `'` is legal in a
        // path, and refusing it would break a call the parser sends verbatim.
        assert!(parse_target("https://api.example.com/o'brien").is_ok());
        assert!(parse_target("https://api.example.com/v1?q=a|b^c").is_ok());
        assert!(parse_target("https://api.example.com/v1?q=%22x%22").is_ok());
        // Percent-encoded, they are ordinary bytes and survive verbatim.
        assert_eq!(
            parse_target("https://api.example.com/v1?amount=1%0A000")
                .unwrap()
                .query
                .as_deref(),
            Some("amount=1%0A000")
        );
        // And ports it refuses: a URL parser accepts `:0`, `Origin` does not,
        // so the authority goes through that one validator rather than being
        // patched in around it.
        assert!(parse_target("https://api.example.com:0/v1").is_err());
        // An ordinary explicit port still survives the round trip.
        let t = parse_target("https://api.example.com:8443/v1").unwrap();
        assert_eq!(t.origin.port, Some(8443));
        // As does the default, which the URL parser reports as absent.
        assert_eq!(
            parse_target("https://api.example.com:443/v1")
                .unwrap()
                .origin
                .port,
            None
        );
    }

    /// The refusal sets are the URL parser's behaviour, not a guess at it —
    /// so they are derived from it here rather than restated. Every printable
    /// ASCII character is put through `Url::parse` in each component: one that
    /// comes back re-spelled must be refused, and one that survives verbatim
    /// must not be (refusing those would break calls the parser would have
    /// sent unchanged). A url-crate change fails this test instead of quietly
    /// reopening the gap between the approved target and the sent one.
    #[test]
    fn every_character_the_parser_respells_is_refused() {
        for b in 0x21u8..=0x7e {
            let c = b as char;
            // Structural characters, refused for their own reasons above.
            if matches!(c, '#' | '?' | '%' | '\\') {
                continue;
            }
            let respelled_in_path = reqwest::Url::parse(&format!("https://h/x{c}y"))
                .map(|u| u.path() != format!("/x{c}y"))
                .unwrap_or(true);
            assert_eq!(
                PATH_RESPELLED.contains(c),
                respelled_in_path,
                "path {c:?}: parser re-spells = {respelled_in_path}"
            );
            let respelled_in_query = reqwest::Url::parse(&format!("https://h/p?a={c}b"))
                .map(|u| u.query() != Some(&format!("a={c}b")))
                .unwrap_or(true);
            assert_eq!(
                QUERY_RESPELLED.contains(c),
                respelled_in_query,
                "query {c:?}: parser re-spells = {respelled_in_query}"
            );
        }
        // Non-ASCII is re-spelled in both, which is why it is refused outright
        // rather than by either list.
        let u = reqwest::Url::parse("https://h/caf\u{e9}?a=\u{e9}").unwrap();
        assert_eq!(u.path(), "/caf%C3%A9");
        assert_eq!(u.query(), Some("a=%C3%A9"));
    }

    #[test]
    fn method_normalization() {
        assert_eq!(normalize_method("get").unwrap(), "GET");
        assert_eq!(normalize_method(" Post ").unwrap(), "POST");
        assert!(normalize_method("bad method").is_err());
        // TRACE is refused locally with the reason, not after an approval.
        let err = normalize_method("trace").unwrap_err();
        assert!(err.contains("reflect"), "{err}");
    }

    #[test]
    fn header_parsing() {
        let (n, v) = parse_header("Content-Type: application/json")
            .unwrap()
            .unwrap();
        assert_eq!(n, "content-type");
        assert_eq!(v, "application/json");
        // Only leading whitespace is dropped; the value is otherwise verbatim.
        assert_eq!(parse_header("X-A:  b c ").unwrap().unwrap().1, "b c ");
        // `Name:` is curl's removal spelling — it must not become a
        // present-but-empty header, which is a different request upstream.
        assert!(parse_header("X-Feature:").unwrap().is_none());
        assert!(parse_header("X-Feature:   ").unwrap().is_none());
        // `Name;` is how curl spells a deliberately empty value.
        assert_eq!(
            parse_header("X-Feature;").unwrap().unwrap(),
            ("x-feature".to_string(), String::new())
        );
        assert!(parse_header(";").is_err());
        // `User-Agent:` is the one removal with something to remove — this CLI
        // sets a default one and the broker forwards it upstream. The parser
        // reports the removal; honouring it is `run_curl`'s job.
        assert!(parse_header("User-Agent:").unwrap().is_none());
        assert!(parse_header("nocolon").is_err());
        assert!(parse_header(": v").is_err());
        assert!(parse_header("Bad Name: v").is_err());
        // OWS is ASCII space and tab. Everything else in Unicode's whitespace
        // class is a value BYTE — curl 8.5.0 sends `X-Sig:\u{a0}abc` as the
        // NBSP bytes followed by abc, and sends `X-Sig:\u{a0}` rather than
        // treating it as the removal spelling. Eating those bytes would
        // shorten a signature copied from a working curl line.
        assert_eq!(parse_header("X-A:\tb").unwrap().unwrap().1, "b");
        assert_eq!(
            parse_header("X-Sig:\u{a0}abc").unwrap().unwrap().1,
            "\u{a0}abc"
        );
        assert_eq!(
            parse_header("X-Sig: \u{a0}").unwrap().unwrap().1,
            "\u{a0}",
            "not empty: NBSP is content, so this is not curl's removal spelling"
        );
        // A name is not a place for Unicode whitespace either: trimming it
        // there would turn an invalid name into a valid-looking different one.
        assert!(parse_header("X-A\u{a0}: v").is_err());
    }

    #[test]
    fn stripped_headers_are_recognized() {
        assert!(is_stripped_header("Authorization"));
        assert!(is_stripped_header("cookie"));
        assert!(is_stripped_header("X-Forwarded-For"));
        assert!(is_stripped_header("x-http-method-override"));
        assert!(!is_stripped_header("content-type"));
        assert!(!is_stripped_header("x-api-version"));
    }

    #[test]
    fn constraints_default_to_exactly_this_call() {
        let t = parse_target("https://api.example.com/v1/things?x=1").unwrap();
        let c = constraints_for(&t, "GET", &[], &[], 300, 1).unwrap();
        assert_eq!(c.origins, vec![t.origin.clone()]);
        assert_eq!(c.methods, vec!["GET"]);
        // The path, not the host: approving one call approves one call.
        assert_eq!(c.path_prefixes, vec!["/v1/things"]);
        assert_eq!(c.ttl_seconds, 300);
        assert_eq!(c.max_uses, Some(1));
    }

    #[test]
    fn constraints_widen_only_when_asked() {
        let t = parse_target("https://api.example.com/v1/things").unwrap();
        let c = constraints_for(
            &t,
            "GET",
            &["post".into(), "GET".into()],
            &["/v1".into()],
            600,
            0,
        )
        .unwrap();
        // Extra methods normalize and dedupe against the primary one.
        assert_eq!(c.methods, vec!["GET", "POST"]);
        assert_eq!(c.path_prefixes, vec!["/v1"]);
        // 0 is "no cap": the server rejects a literal 0 and reads a missing
        // max_uses as unlimited-within-TTL.
        assert_eq!(c.max_uses, None);
        // A prefix that is not a path would silently never match.
        assert!(constraints_for(&t, "GET", &[], &["v1".into()], 600, 1).is_err());
    }

    /// Minimal args for body tests: only the data fields matter.
    fn body_args(
        data: Option<&str>,
        data_raw: Option<&str>,
        data_binary: Option<&str>,
    ) -> CurlArgs {
        body_args_multi(
            data.into_iter().collect(),
            data_raw.into_iter().collect(),
            data_binary.into_iter().collect(),
        )
    }

    fn body_args_multi(data: Vec<&str>, data_raw: Vec<&str>, data_binary: Vec<&str>) -> CurlArgs {
        CurlArgs {
            url: "https://api.example.com/v1".into(),
            secret: None,
            method: None,
            headers: vec![],
            data: data.iter().map(|s| (*s).to_owned()).collect(),
            data_raw: data_raw.iter().map(|s| (*s).to_owned()).collect(),
            data_binary: data_binary.iter().map(|s| (*s).to_owned()).collect(),
            output: None,
            include: false,
            fail: false,
            reason: String::new(),
            ttl: 300,
            max_uses: 1,
            timeout: 900,
            max_time: 120.0,
            idempotency_key: None,
            grant_id: None,
            path_prefixes: vec![],
            allow_methods: vec![],
        }
    }

    #[test]
    fn body_sources_follow_curls_spelling() {
        assert_eq!(
            read_body(&body_args(Some("plain"), None, None))
                .unwrap()
                .unwrap(),
            b"plain"
        );
        // --data-raw takes the argument literally, @ and all.
        assert_eq!(
            read_body(&body_args(None, Some("@literal"), None))
                .unwrap()
                .unwrap(),
            b"@literal"
        );
        assert_eq!(read_body(&body_args(None, None, None)).unwrap(), None);
        let dir = std::env::temp_dir().join(format!("keychute-curl-{}", Uuid::new_v4()));
        std::fs::write(&dir, b"from-file").unwrap();
        let path = format!("@{}", dir.display());
        assert_eq!(
            read_body(&body_args(Some(&path), None, None))
                .unwrap()
                .unwrap(),
            b"from-file"
        );
        std::fs::remove_file(&dir).unwrap();
        assert!(read_body(&body_args(Some("@/nonexistent/keychute-test"), None, None)).is_err());
    }

    #[test]
    fn file_bodies_are_stripped_the_way_curl_strips_them() {
        // Every case verified against curl 8.5.0 through a recording server:
        // curl truncates each line at its first CR or NUL rather than dropping
        // those bytes individually, so `a\0b\r\nc` is `ac`, not `abc`.
        for (input, want) in [
            (&b"a\x00b\r\nc"[..], &b"ac"[..]),
            (b"a\rb\nc", b"ac"),
            (b"a\nb\nc", b"abc"),
            (b"a\r\nb\r\nc", b"abc"),
            (b"a\x00b", b"a"),
            (b"\x00abc", b""),
            (b"ab\x00", b"ab"),
            (b"a\n\x00b\nc", b"ac"),
            // The ordinary case, unchanged: a text file's line endings go.
            (b"one\ntwo\n", b"onetwo"),
        ] {
            assert_eq!(
                strip_like_curl(input),
                want,
                "stripping {input:?} should give {want:?}"
            );
        }
    }

    #[test]
    fn an_empty_idempotency_key_is_refused() {
        let target = parse_target("https://api.example.com/v1/things").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/v1/things".into();
        args.secret = Some("s".into());

        // An unset variable that expanded, not a choice — and one that would
        // otherwise derive the same key on every call and resume an earlier
        // approval instead of pushing a new one.
        args.idempotency_key = Some(String::new());
        let err = validate_grant_options(&args, &target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("empty"), "{}", err.message);

        args.idempotency_key = Some("deliberate-key".into());
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
        args.idempotency_key = None;
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
    }

    #[test]
    fn a_target_too_long_for_the_approval_context_is_refused() {
        // Shedding drops capture sections; the target is not one of them, so a
        // URL whose own query fills the cap leaves a map nothing can shrink
        // and a request the server will certainly reject.
        let huge = format!(
            "https://api.example.com/v1/things?q={}",
            "x".repeat(crate::MAX_STRUCTURED_BYTES)
        );
        let target = parse_target(&huge).unwrap();
        let err = build_request_context(&target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("approval context"), "{}", err.message);

        // An ordinary target fits, and carries the method and URL the operator
        // reads.
        let target = parse_target("https://api.example.com/v1/things?a=1").unwrap();
        let ctx = build_request_context(&target, "POST").unwrap();
        assert_eq!(
            ctx["target"],
            serde_json::json!("POST https://api.example.com/v1/things?a=1")
        );
    }

    #[test]
    fn max_time_takes_curls_fractional_seconds() {
        let target = parse_target("https://api.example.com/v1/things").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/v1/things".into();
        args.secret = Some("s".into());

        // curl's own spelling for a sub-second deadline.
        args.max_time = 0.5;
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
        // 0 is "no limit", which is why it is not rejected as too small.
        args.max_time = 0.0;
        assert!(validate_grant_options(&args, &target, "GET").is_ok());

        // `Duration::from_secs_f64` panics on each of these, so none may reach
        // it.
        for bad in [-1.0, f64::NAN, f64::INFINITY, 1e30] {
            args.max_time = bad;
            assert!(
                validate_grant_options(&args, &target, "GET").is_err(),
                "--max-time {bad} must be refused"
            );
        }
    }

    #[test]
    fn the_output_cannot_create_the_body_it_is_about_to_read() {
        // `-d @payload -o payload`. Opening the output first would create the
        // missing input, and the invocation that deserved "no such file" would
        // instead spend an approval sending an empty body.
        let dir = std::env::temp_dir().join(format!("keychute-io-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let shared = dir.join("payload");

        let mut args = body_args(Some(&format!("@{}", shared.display())), None, None);
        args.output = Some(shared.clone());
        let err = open_body_sources(&args).unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(
            err.message.contains("cannot read body file"),
            "{}",
            err.message
        );
        assert!(
            !shared.exists(),
            "nothing was created on the way to failing"
        );

        // With the input actually there, the handle is taken before the output
        // opens, so the original bytes are what gets sent.
        std::fs::write(&shared, b"a=1").unwrap();
        let sources = open_body_sources(&args).unwrap();
        assert!(open_output(&args).unwrap().is_some());
        assert_eq!(
            read_body_with(&args, 1024, sources).unwrap().unwrap(),
            b"a=1"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn data_strips_newlines_from_files_but_data_binary_does_not() {
        // curl's rule: -d on file/stdin input drops CR and LF (a form body
        // should not carry the editor's line breaks), --data-binary keeps
        // every byte. Swapping curl for keychute curl must not change what
        // arrives upstream.
        let path = std::env::temp_dir().join(format!("keychute-nl-{}", Uuid::new_v4()));
        std::fs::write(&path, b"a=1\r\nb=2\n").unwrap();
        let arg = format!("@{}", path.display());
        assert_eq!(
            read_body(&body_args(Some(&arg), None, None))
                .unwrap()
                .unwrap(),
            b"a=1b=2"
        );
        assert_eq!(
            read_body(&body_args(None, None, Some(&arg)))
                .unwrap()
                .unwrap(),
            b"a=1\r\nb=2\n"
        );
        // An inline -d value is taken literally either way — the stripping is
        // a property of file/stdin input, not of the flag.
        assert_eq!(
            read_body(&body_args(Some("a=1\nb=2"), None, None))
                .unwrap()
                .unwrap(),
            b"a=1\nb=2"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn connection_nominated_headers_are_resolved_before_connection_is_dropped() {
        let headers = vec![
            ("connection".to_string(), "X-Internal, close".to_string()),
            ("x-internal".to_string(), "v".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let nominated = connection_nominated(&headers);
        assert!(nominated.contains(&"x-internal".to_string()));
        assert!(nominated.contains(&"close".to_string()));
        assert!(!nominated.contains(&"content-type".to_string()));
        // No Connection header nominates nothing.
        assert!(connection_nominated(&headers[1..]).is_empty());
    }

    #[test]
    fn canonical_paths_match_what_the_grant_stores() {
        // The grant holds the decoded prefix; the URL holds the raw path.
        assert_eq!(canonical_path("/files/a%20b").unwrap(), "/files/a b");
        assert!(path_covered(
            "/files/a b",
            &canonical_path("/files/a%20b").unwrap()
        ));
        assert_eq!(canonical_path("/v1/things").unwrap(), "/v1/things");
        // Paths the server rejects outright have no canonical form here
        // either, so the local check defers instead of guessing.
        assert!(canonical_path("/v1%2Fthings").is_none());
        assert!(canonical_path("/v1\\things").is_none());
        assert!(canonical_path("/v1%zz").is_none());
        assert!(canonical_path("/v1%").is_none());
        assert!(canonical_path("/v1/../admin").is_none());
        assert!(canonical_path("/v1/%2e%2e/admin").is_none());
        // Path parameters: a servlet-family upstream strips `;x` and only then
        // normalizes, so `..;x` is a dot segment. The server judges each
        // segment by the part before `;`, and so must this — otherwise
        // `/v1/..;x` looks covered by `/v1`, spends an approval, and is
        // refused by the proxy.
        assert!(canonical_path("/v1/..;x").is_none());
        assert!(canonical_path("/v1/..%3bjsessionid=1").is_none());
        assert!(canonical_path("/v1/.;/admin").is_none());
        // A `;` on an ordinary segment is not a dot segment.
        assert_eq!(canonical_path("/v1/things;v=2").unwrap(), "/v1/things;v=2");
        // The server's remaining refusals, mirrored for the same reason.
        assert!(canonical_path("/v1//things").is_none());
        assert!(canonical_path("/v1/th\ning").is_none());
    }

    #[test]
    fn a_ttl_outside_the_servers_bounds_is_refused_before_the_body_is_read() {
        let target = parse_target("https://api.example.com/v1/things").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/v1/things".into();
        args.secret = Some("s".into());

        args.ttl = 0;
        let err = validate_grant_options(&args, &target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("--ttl"), "{}", err.message);

        args.ttl = MAX_TTL_SECONDS + 1;
        assert!(validate_grant_options(&args, &target, "GET").is_err());

        args.ttl = MAX_TTL_SECONDS;
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
    }

    #[test]
    fn a_constraint_list_past_the_servers_cap_is_refused_before_the_body_is_read() {
        let target = parse_target("https://api.example.com/v1/things").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/v1/things".into();
        args.secret = Some("s".into());

        args.path_prefixes = vec!["/".into(); MAX_CONSTRAINT_ENTRIES + 1];
        let err = validate_grant_options(&args, &target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("--path-prefix"), "{}", err.message);

        args.path_prefixes = vec!["/".into(); MAX_CONSTRAINT_ENTRIES];
        assert!(validate_grant_options(&args, &target, "GET").is_ok());

        // Methods are deduplicated first, so repetition alone is not a
        // rejection however often it is spelled.
        args.allow_methods = vec!["get".into(); MAX_CONSTRAINT_ENTRIES + 1];
        assert!(validate_grant_options(&args, &target, "GET").is_ok());

        // The call's own method is one of the entries. A set that fills the
        // cap on its own therefore fits only if the method is already in it —
        // which is the whole reason the method is inferred before this runs.
        args.allow_methods = (0..MAX_CONSTRAINT_ENTRIES)
            .map(|i| format!("M{i}"))
            .collect();
        let err = validate_grant_options(&args, &target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("counting GET"), "{}", err.message);

        args.allow_methods[0] = "GET".into();
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
        // The same 32 with a POST body: now nothing covers the call's method,
        // and the server would have rejected 33 entries after stdin was read.
        assert!(validate_grant_options(&args, &target, "POST").is_err());
    }

    #[test]
    fn a_secret_name_is_only_judged_when_the_grant_would_use_it() {
        let target = parse_target("https://api.example.com/v1/things").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/v1/things".into();
        args.secret = Some(String::new());

        let err = validate_grant_options(&args, &target, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("--secret"), "{}", err.message);

        // With `--grant-id` the name is ignored, and saying so then rejecting
        // the call over it would be the same argument answered two ways.
        args.grant_id = Some(Uuid::nil().to_string());
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
        args.secret = Some("x".repeat(MAX_SECRET_NAME_BYTES + 1));
        assert!(validate_grant_options(&args, &target, "GET").is_ok());
    }

    #[test]
    fn an_unopenable_output_target_is_refused_before_the_body_is_read() {
        let mut args = body_args(None, None, None);
        let dir = std::env::temp_dir().join(format!("keychute-out-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // Each of these looks different to `exists`/`is_dir` and identical to
        // `open`, which is why the check IS the open.
        for unopenable in [
            // A directory.
            dir.clone(),
            // A missing parent.
            dir.join("nope").join("out.json"),
        ] {
            args.output = Some(unopenable.clone());
            let err = open_output(&args).unwrap_err();
            assert_eq!(err.code, EXIT_CONFIG, "{}", unopenable.display());
        }

        // A symlink to nowhere: its parent is a directory and it is not one
        // itself, so nothing short of opening it tells the truth.
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nope").join("target"), &dangling).unwrap();
        args.output = Some(dangling);
        assert_eq!(open_output(&args).unwrap_err().code, EXIT_CONFIG);

        // An existing file is opened WITHOUT truncation: an approval that ends
        // in a denial must not have destroyed it.
        let existing = dir.join("existing");
        std::fs::write(&existing, b"keep me").unwrap();
        args.output = Some(existing.clone());
        assert!(open_output(&args).unwrap().is_some());
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");

        // Stdout, spelled either way, needs no file at all.
        args.output = None;
        assert!(open_output(&args).unwrap().is_none());
        args.output = Some("-".into());
        assert!(open_output(&args).unwrap().is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversize_body_fails_locally() {
        let mut buf = Vec::new();
        assert!(read_bounded(std::io::repeat(b'x'), &mut buf, 1024).is_err());
        assert!(buf.is_empty());
        let mut buf = Vec::new();
        read_bounded(vec![b'x'; 1024].as_slice(), &mut buf, 1024).unwrap();
        assert_eq!(buf.len(), 1024);
    }

    #[test]
    fn the_read_bound_is_configurable_and_validated() {
        // A body under an explicit bound reads fine...
        assert_eq!(
            read_body_bounded(&body_args(Some("hello"), None, None), 5)
                .unwrap()
                .unwrap(),
            b"hello"
        );
        // ...and the bound is on the WHOLE body, not on each read. An inline
        // piece never passes through the bounded reader at all, and neither do
        // the `&` separators — three empty files still assemble two bytes.
        assert!(read_body_bounded(&body_args(Some("hello"), None, None), 4).is_err());
        let empty = std::env::temp_dir().join(format!("keychute-empty-{}", Uuid::new_v4()));
        std::fs::write(&empty, b"").unwrap();
        let at_empty = format!("@{}", empty.display());
        let three = body_args_multi(vec![&at_empty, &at_empty, &at_empty], vec![], vec![]);
        assert_eq!(read_body_bounded(&three, 2).unwrap().unwrap(), b"&&");
        let err = read_body_bounded(&three, 1).unwrap_err();
        assert!(err.message.contains(MAX_BODY_ENV), "{}", err.message);
        std::fs::remove_file(&empty).unwrap();
        let path = std::env::temp_dir().join(format!("keychute-bound-{}", Uuid::new_v4()));
        std::fs::write(&path, b"0123456789").unwrap();
        let arg = format!("@{}", path.display());
        assert_eq!(
            read_body_bounded(&body_args(Some(&arg), None, None), 10)
                .unwrap()
                .unwrap(),
            b"0123456789"
        );
        // ...and over it fails with a message naming the override, since the
        // bound is ours and the deployment's real cap may be higher.
        let err = read_body_bounded(&body_args(Some(&arg), None, None), 9).unwrap_err();
        assert!(err.message.contains(MAX_BODY_ENV), "{}", err.message);
        assert_eq!(err.code, EXIT_CONFIG);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_credential_selector_is_decided_from_arguments_alone() {
        // Resolvable without touching stdin or the network, which is what
        // lets it run before `-d @-` consumes a producer.
        let mut args = body_args(None, None, None);
        assert!(matches!(
            credential_selector(&args),
            Err(f) if f.code == EXIT_CONFIG && f.message.contains("--secret")
        ));
        args.secret = Some("example-api-token".into());
        assert!(
            matches!(credential_selector(&args), Ok(Selector::Secret(s)) if s == "example-api-token")
        );
        args.grant_id = Some("22222222-2222-2222-2222-222222222222".into());
        assert!(matches!(credential_selector(&args), Ok(Selector::Grant(_))));
        args.grant_id = Some("not-a-uuid".into());
        assert!(credential_selector(&args).is_err());
    }

    #[test]
    fn path_coverage_matches_at_segment_boundaries() {
        assert!(path_covered("/v1/account", "/v1/account"));
        assert!(path_covered("/v1/account", "/v1/account/settings"));
        // The trap the server's own rule exists to close.
        assert!(!path_covered("/v1/account", "/v1/account-delete"));
        assert!(!path_covered("/v1/account", "/v1/other"));
        // A trailing slash on the prefix means the same prefix.
        assert!(path_covered("/v1/account/", "/v1/account/x"));
        // Root covers everything.
        assert!(path_covered("/", "/anything"));
    }

    #[test]
    fn the_idempotency_key_is_bound_to_the_exact_call() {
        let base = parse_target("https://api.example.com/transfer?to=trusted").unwrap();
        let key = call_bound_idempotency_key("k1", "POST", &base, &[], None);
        // Same command, same key: a rerun resumes its original request, which
        // is the whole point of --idempotency-key.
        assert_eq!(
            key,
            call_bound_idempotency_key("k1", "POST", &base, &[], None)
        );

        // Change ONLY the query and the key changes — otherwise the server
        // would hand back the original approval (the MAC excludes
        // context.structured) and this command would proxy the new target
        // under a grant the operator approved for the old one.
        let swapped = parse_target("https://api.example.com/transfer?to=attacker").unwrap();
        assert_ne!(
            key,
            call_bound_idempotency_key("k1", "POST", &swapped, &[], None)
        );
        // Same for the other components of "which call is this".
        let other_path = parse_target("https://api.example.com/refund?to=trusted").unwrap();
        assert_ne!(
            key,
            call_bound_idempotency_key("k1", "POST", &other_path, &[], None)
        );
        let other_host = parse_target("https://other.example/transfer?to=trusted").unwrap();
        assert_ne!(
            key,
            call_bound_idempotency_key("k1", "POST", &other_host, &[], None)
        );
        assert_ne!(
            key,
            call_bound_idempotency_key("k1", "GET", &base, &[], None)
        );
        // An absent query and an empty one are different request targets —
        // `/transfer?` really is sent with the `?` — so they must not alias.
        let no_query = parse_target("https://api.example.com/transfer").unwrap();
        let empty_query = parse_target("https://api.example.com/transfer?").unwrap();
        assert_eq!(no_query.query, None);
        assert_eq!(empty_query.query.as_deref(), Some(""));
        assert_ne!(
            call_bound_idempotency_key("k1", "POST", &no_query, &[], None),
            call_bound_idempotency_key("k1", "POST", &empty_query, &[], None)
        );
        // A different caller key is still a different request.
        assert_ne!(
            key,
            call_bound_idempotency_key("k2", "POST", &base, &[], None)
        );
        // Length-prefixing: no field boundary can be shifted to collide.
        let a = parse_target("https://api.example.com/ab").unwrap();
        let b = parse_target("https://api.example.com/a?b").unwrap();
        assert_ne!(
            call_bound_idempotency_key("k", "GET", &a, &[], None),
            call_bound_idempotency_key("k", "GET", &b, &[], None)
        );
        // The body and the forwarded headers are part of "which call is
        // this" too: neither is in `CreateAccessRequest`, so without them a
        // rerun keeping the key sends new bytes under the old approval.
        let hdrs = vec![("x-signature".to_string(), "abc".to_string())];
        assert_ne!(
            call_bound_idempotency_key("k1", "POST", &base, &[], Some(b"{\"to\":\"trusted\"}")),
            call_bound_idempotency_key("k1", "POST", &base, &[], Some(b"{\"to\":\"attacker\"}"))
        );
        assert_ne!(
            key,
            call_bound_idempotency_key("k1", "POST", &base, &hdrs, None)
        );
        assert_ne!(
            call_bound_idempotency_key("k1", "POST", &base, &hdrs, None),
            call_bound_idempotency_key(
                "k1",
                "POST",
                &base,
                &[("x-signature".to_string(), "xyz".to_string())],
                None
            )
        );
        // Order is part of the request too.
        let a_then_b = vec![
            ("x-a".to_string(), "1".to_string()),
            ("x-b".to_string(), "2".to_string()),
        ];
        let b_then_a = vec![
            ("x-b".to_string(), "2".to_string()),
            ("x-a".to_string(), "1".to_string()),
        ];
        assert_ne!(
            call_bound_idempotency_key("k1", "POST", &base, &a_then_b, None),
            call_bound_idempotency_key("k1", "POST", &base, &b_then_a, None)
        );
        // No body and an empty body are different requests: `-d ''` sends
        // `Content-Length: 0`.
        assert_ne!(
            call_bound_idempotency_key("k1", "POST", &base, &[], None),
            call_bound_idempotency_key("k1", "POST", &base, &[], Some(b""))
        );
        // Length-prefixing again, across the new fields.
        assert_ne!(
            call_bound_idempotency_key(
                "k1",
                "POST",
                &base,
                &[("x-a".to_string(), "bc".to_string())],
                None
            ),
            call_bound_idempotency_key(
                "k1",
                "POST",
                &base,
                &[("x-ab".to_string(), "c".to_string())],
                None
            )
        );
        // The derived key fits the server's cap.
        assert!(validate_idempotency_key(&call_bound_idempotency_key(
            &"k".repeat(MAX_CURL_USER_KEY_BYTES),
            "POST",
            &base,
            &[],
            None
        ))
        .is_ok());
        // …and keeps 128 bits of the digest. This is a COLLISION bound, and
        // the party searching is the one choosing both queries: find two that
        // hash alike, get the benign one approved, run the other under it. At
        // 64 bits that is a ~2^32 search, which is the substitution this
        // binding exists to prevent.
        let suffix = key.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 32, "128 bits of digest, hex-encoded");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn encoded_dot_segments_reach_the_server_unresolved() {
        // `reqwest::Url` resolves dot segments at parse time, encoded ones
        // included, so taking the path from it would send this call to
        // /admin — a resource the caller never named — and launder past the
        // server check that exists to reject it.
        let t = parse_target("https://api.example.com/a/%2e%2e/admin").unwrap();
        assert_eq!(t.path, "/a/%2e%2e/admin");
        // No canonical form locally either, so the local checks defer and the
        // server returns invalid-path.
        assert!(canonical_path(&t.path).is_none());
        // A literal `/../` is equally preserved.
        let t = parse_target("https://api.example.com/a/../admin").unwrap();
        assert_eq!(t.path, "/a/../admin");
        assert!(canonical_path(&t.path).is_none());
        // Ordinary paths and queries are unaffected.
        let t = parse_target("https://api.example.com/v1/things?x=1&y=2").unwrap();
        assert_eq!(t.path, "/v1/things");
        assert_eq!(t.query.as_deref(), Some("x=1&y=2"));
        assert_eq!(parse_target("https://api.example.com").unwrap().path, "/");
        let t = parse_target("https://api.example.com?x=1").unwrap();
        assert_eq!(t.path, "/");
        assert_eq!(t.query.as_deref(), Some("x=1"));
        // A backslash makes the URL mean two things at once — the WHATWG
        // parser reads `https://api.example\admin` as `/admin`, the raw
        // extractor as `/` — so it is refused rather than approved as one and
        // sent as the other.
        for raw in [
            "https://api.example\\admin",
            "https://api.example.com/a\\b",
            "https://api.example.com/v1?x=a\\b",
        ] {
            let err = parse_target(raw).unwrap_err();
            assert!(err.contains("backslash"), "{raw}: {err}");
        }
        // Encoded, no parser rewrites it, so it reaches the server intact and
        // the server is the one that refuses it — same deference as a dot
        // segment: no local canonical form, so no local coverage claim.
        let t = parse_target("https://api.example.com/a%5Cb").unwrap();
        assert_eq!(t.path, "/a%5Cb");
        assert!(canonical_path(&t.path).is_none());
        // A port in the authority is not mistaken for the path.
        let t = parse_target("https://api.example.com:8443/v1").unwrap();
        assert_eq!(t.path, "/v1");
        assert_eq!(t.origin.port, Some(8443));
    }

    #[test]
    fn an_empty_first_data_piece_still_separates() {
        // curl merges pieces with `&` by position, so an empty first piece
        // yields a LEADING separator. A body that differs by one byte can
        // invalidate a signature.
        assert_eq!(
            read_body(&body_args_multi(vec!["", "action=delete"], vec![], vec![]))
                .unwrap()
                .unwrap(),
            b"&action=delete"
        );
        assert_eq!(
            read_body(&body_args_multi(vec!["a=1", "", "b=2"], vec![], vec![]))
                .unwrap()
                .unwrap(),
            b"a=1&&b=2"
        );
    }

    #[test]
    fn a_body_limit_with_no_room_for_the_lookahead_is_refused() {
        // usize::MAX would wrap `limit + 1` to zero and make the reader take
        // NOTHING — an @file request silently sending an empty body.
        let err = parse_max_body(Some(&usize::MAX.to_string())).unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(parse_max_body(Some("0")).is_err());
        assert!(parse_max_body(Some("not-a-number")).is_err());
        assert_eq!(parse_max_body(Some("4096")).unwrap(), 4096);
        assert_eq!(parse_max_body(None).unwrap(), DEFAULT_MAX_BODY_BYTES);
        // The reader itself is safe against a bound passed directly, too.
        let mut buf = Vec::new();
        assert!(read_bounded(std::io::repeat(b'x'), &mut buf, 64).is_err());
    }

    #[test]
    fn grant_options_are_validated_from_arguments_alone() {
        // These all run before the body is read, so `-d @-` cannot block an
        // invocation that is already known to be invalid.
        let t = parse_target("https://api.example.com/admin").unwrap();
        let mut args = body_args(None, None, None);
        args.url = "https://api.example.com/admin".into();
        args.secret = Some("s".into());
        assert!(validate_grant_options(&args, &t, "GET").is_ok());

        args.allow_methods = vec!["TRACE".into()];
        assert!(validate_grant_options(&args, &t, "GET").is_err());
        args.allow_methods = vec![];

        args.path_prefixes = vec!["v1".into()];
        assert!(
            validate_grant_options(&args, &t, "GET").is_err(),
            "relative prefix"
        );
        args.path_prefixes = vec!["/v1".into()];
        assert!(
            validate_grant_options(&args, &t, "GET").is_err(),
            "prefix that cannot cover the call"
        );
        args.path_prefixes = vec!["/admin".into()];
        assert!(validate_grant_options(&args, &t, "GET").is_ok());

        args.idempotency_key = Some("k".repeat(MAX_CURL_USER_KEY_BYTES + 1));
        assert!(validate_grant_options(&args, &t, "GET").is_err());
        args.idempotency_key = None;

        // A path the proxy will refuse is refused here, even when the prefix
        // that would be approved is itself perfectly valid — otherwise a human
        // approves `/v1` and the call dies at the proxy anyway.
        let doomed = parse_target("https://api.example.com/v1/..;jsessionid=1").unwrap();
        args.path_prefixes = vec!["/v1".into()];
        let err = validate_grant_options(&args, &doomed, "GET").unwrap_err();
        assert_eq!(err.code, EXIT_CONFIG);
        assert!(err.message.contains("refuses"), "{}", err.message);
        args.path_prefixes = vec!["/admin".into()];

        // The server's remaining fixed bounds, each certain to be refused on
        // arrival and each decidable here.
        args.max_uses = MAX_SERVER_USES + 1;
        assert!(validate_grant_options(&args, &t, "GET").is_err());
        args.max_uses = MAX_SERVER_USES;
        assert!(validate_grant_options(&args, &t, "GET").is_ok());
        args.max_uses = 1;

        args.secret = Some(String::new());
        assert!(
            validate_grant_options(&args, &t, "GET").is_err(),
            "empty name"
        );
        args.secret = Some("s".repeat(MAX_SECRET_NAME_BYTES + 1));
        assert!(
            validate_grant_options(&args, &t, "GET").is_err(),
            "name too long"
        );
        args.secret = Some("s".into());

        args.reason = "r".repeat(MAX_REASON_BYTES + 1);
        assert!(validate_grant_options(&args, &t, "GET").is_err());
        args.reason = String::new();

        // `--timeout` becomes an `Instant`, so a value that overflows the
        // addition has to be refused as the configuration error it is rather
        // than panicking after stdin has been consumed.
        args.timeout = u64::MAX;
        assert!(validate_grant_options(&args, &t, "GET").is_err());
        args.timeout = MAX_APPROVAL_WAIT_SECONDS;
        assert!(validate_grant_options(&args, &t, "GET").is_ok());

        // The destination is proved by `open_output`, tested separately: it
        // opens the file, which no amount of inspecting the path can replace.
    }

    #[test]
    fn repeated_data_pieces_merge_with_an_ampersand() {
        // curl's rule, and the reason `-d a=1 -d b=2` is a form body rather
        // than a usage error.
        assert_eq!(
            read_body(&body_args_multi(
                vec!["name=daniel", "skill=lousy"],
                vec![],
                vec![]
            ))
            .unwrap()
            .unwrap(),
            b"name=daniel&skill=lousy"
        );
        assert_eq!(
            read_body(&body_args_multi(vec![], vec!["@a", "@b"], vec![]))
                .unwrap()
                .unwrap(),
            b"@a&@b",
            "--data-raw stays literal, including the @"
        );
        // A file piece merges with an inline one, and CR/LF still go for -d.
        let path = std::env::temp_dir().join(format!("keychute-merge-{}", Uuid::new_v4()));
        std::fs::write(&path, b"b=2\n").unwrap();
        let arg = format!("@{}", path.display());
        assert_eq!(
            read_body(&body_args_multi(vec!["a=1", &arg], vec![], vec![]))
                .unwrap()
                .unwrap(),
            b"a=1&b=2"
        );
        // --data-binary merges too, byte for byte.
        assert_eq!(
            read_body(&body_args_multi(vec![], vec![], vec!["a=1", &arg]))
                .unwrap()
                .unwrap(),
            b"a=1&b=2\n"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn repeated_data_flags_parse_and_mixing_flavours_does_not() {
        use clap::Parser as _;
        let cli = crate::Cli::parse_from([
            "keychute",
            "curl",
            "https://api.example.com/x",
            "--secret",
            "s",
            "-d",
            "name=daniel",
            "-d",
            "skill=lousy",
        ]);
        match cli.cmd {
            crate::Cmd::Curl(args) => {
                assert_eq!(args.data, vec!["name=daniel", "skill=lousy"])
            }
            _ => panic!("expected curl subcommand"),
        }
        // Mixing flavours would need curl's command-line ordering, which this
        // parser cannot reproduce faithfully — so it is refused rather than
        // silently reordered.
        assert!(crate::Cli::try_parse_from([
            "keychute",
            "curl",
            "https://api.example.com/x",
            "--secret",
            "s",
            "-d",
            "a=1",
            "--data-binary",
            "b=2",
        ])
        .is_err());
    }

    #[test]
    fn a_path_prefix_that_excludes_the_call_is_refused() {
        let t = parse_target("https://api.example.com/admin").unwrap();
        // Approving this would mint a grant whose very first use is a certain
        // 403 — an operator's attention spent on a call that cannot work.
        let err = constraints_for(&t, "GET", &[], &["/v1".into()], 300, 1).unwrap_err();
        assert!(err.contains("does not cover"), "{err}");
        // A covering prefix is fine, at either granularity.
        assert!(constraints_for(&t, "GET", &[], &["/admin".into()], 300, 1).is_ok());
        assert!(constraints_for(&t, "GET", &[], &["/".into()], 300, 1).is_ok());
        // And one of several covering is enough.
        assert!(constraints_for(&t, "GET", &[], &["/v1".into(), "/admin".into()], 300, 1).is_ok());
        // Encoded paths compare canonically, like the server does — and that
        // has to hold from BOTH sides, since the server canonicalizes every
        // prefix it stores. An encoded prefix for an encoded target is the
        // same call and must not be refused.
        let enc = parse_target("https://api.example.com/files/a%20b").unwrap();
        assert!(constraints_for(&enc, "GET", &[], &["/files/a b".into()], 300, 1).is_ok());
        assert!(constraints_for(&enc, "GET", &[], &["/files/a%20b".into()], 300, 1).is_ok());
        // A prefix with no canonical form is a configuration error, not a
        // guess to defer: `api/requests.rs` canonicalizes every prefix it is
        // sent and rejects the request when one fails, so this can only end in
        // an invalid-request — and deferring would let `-d @-` block on a
        // producer first. Each spelling the server refuses, refused here.
        for bad in [
            "/files%2Fa",
            "/files\\a",
            "/files/../admin",
            "/files/%2e%2e/admin",
            "/files//a",
            "/files/a%zz",
            "/files/a%",
            "/files/..;x",
        ] {
            let err = constraints_for(&enc, "GET", &[], &[bad.into()], 300, 1).unwrap_err();
            assert!(
                err.contains("the broker refuses"),
                "{bad} should be refused locally, got {err}"
            );
        }
    }

    fn err_body(code: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"m"}}}}"#)
    }

    #[test]
    fn keychute_errors_map_to_the_shared_exit_codes() {
        let denied =
            classify_proxy_error(reqwest::StatusCode::FORBIDDEN, &err_body("policy-denied"));
        assert_eq!(denied.code, EXIT_DENIED);
        assert_eq!(
            classify_proxy_error(
                reqwest::StatusCode::UNAUTHORIZED,
                &err_body("unauthenticated")
            )
            .code,
            EXIT_CONFIG
        );
        assert_eq!(
            classify_proxy_error(
                reqwest::StatusCode::PAYLOAD_TOO_LARGE,
                &err_body("body-too-large")
            )
            .code,
            EXIT_CONFIG
        );
        // 410 keeps `request`'s three-way split.
        assert_eq!(
            classify_proxy_error(reqwest::StatusCode::GONE, &err_body("grant-expired")).code,
            crate::EXIT_TIMEOUT
        );
        assert_eq!(
            classify_proxy_error(reqwest::StatusCode::GONE, &err_body("payload-lost")).code,
            crate::EXIT_PAYLOAD_LOST
        );
        // Upstream-shaped statuses that only Keychute produces stay generic.
        assert_eq!(
            classify_proxy_error(
                reqwest::StatusCode::BAD_GATEWAY,
                &err_body("upstream-unreachable")
            )
            .code,
            EXIT_OTHER
        );
    }
}
