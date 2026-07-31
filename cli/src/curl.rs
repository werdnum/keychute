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

/// Overrides [`DEFAULT_MAX_BODY_BYTES`], for a deployment whose
/// `limits.proxy_max_body_bytes` is not the default.
const MAX_BODY_ENV: &str = "KEYCHUTE_MAX_BODY_BYTES";

/// The effective local read bound. An unparseable or zero value is a config
/// error rather than a silent fallback: quietly using a different bound than
/// the one asked for is how a body gets truncated without anyone noticing.
fn max_body_bytes() -> CliResult<usize> {
    match std::env::var(MAX_BODY_ENV) {
        Err(_) => Ok(DEFAULT_MAX_BODY_BYTES),
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(fail(
                EXIT_CONFIG,
                format!("{MAX_BODY_ENV} must be a positive byte count, got {raw:?}"),
            )),
        },
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
    /// Extra request header, `Name: value`. Repeatable.
    #[arg(short = 'H', long = "header", value_name = "LINE")]
    pub headers: Vec<String>,
    /// Request body. `@path` reads a file, `@-` reads stdin (curl's spelling).
    /// Unlike curl, this does NOT imply a Content-Type: pass one with -H.
    #[arg(short = 'd', long = "data", value_name = "DATA")]
    pub data: Option<String>,
    /// Request body taken literally, `@` and all.
    #[arg(long = "data-raw", value_name = "DATA", conflicts_with = "data")]
    pub data_raw: Option<String>,
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
    /// Deadline for the proxied call itself, in seconds.
    #[arg(long, default_value_t = 120)]
    pub max_time: u64,
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
    if url.fragment().is_some() {
        return Err(format!(
            "URL fragment in {raw:?} is never sent to a server; drop it"
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("URL {raw:?} has no host"))?;
    let mut origin = Origin::parse(host)?;
    origin.port = url.port();
    Ok(Target {
        origin,
        path: url.path().to_string(),
        query: url.query().map(|q| q.to_string()),
    })
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
pub(crate) fn parse_header(line: &str) -> Result<(String, String), String> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| format!("header {line:?} is not in `Name: value` form"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("header {line:?} has an empty name"));
    }
    reqwest::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("invalid header name in {line:?}"))?;
    let value = value.trim_start();
    reqwest::header::HeaderValue::from_str(value)
        .map_err(|_| format!("invalid header value in {line:?}"))?;
    Ok((name.to_ascii_lowercase(), value.to_string()))
}

/// Would the broker drop this header? Not fatal, but silence would be worse:
/// the call would go out looking like it carried something it did not.
pub(crate) fn is_stripped_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    STRIPPED_HEADERS.contains(&n.as_str()) || n.starts_with("x-forwarded-")
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

/// Read the request body. `@path` is a file, `@-` is stdin, anything else is
/// the literal argument (curl's rules); `--data-raw` skips the `@` reading.
fn read_body(data: Option<&str>, data_raw: Option<&str>) -> CliResult<Option<Vec<u8>>> {
    read_body_bounded(data, data_raw, max_body_bytes()?)
}

fn read_body_bounded(
    data: Option<&str>,
    data_raw: Option<&str>,
    limit: usize,
) -> CliResult<Option<Vec<u8>>> {
    if let Some(raw) = data_raw {
        return Ok(Some(raw.as_bytes().to_vec()));
    }
    let Some(data) = data else {
        return Ok(None);
    };
    let Some(source) = data.strip_prefix('@') else {
        return Ok(Some(data.as_bytes().to_vec()));
    };
    let mut buf = Vec::new();
    if source == "-" {
        read_bounded(std::io::stdin().lock(), &mut buf, limit)
            .map_err(|e| fail(EXIT_CONFIG, format!("cannot read the body from stdin: {e}")))?;
    } else {
        let file = std::fs::File::open(source)
            .map_err(|e| fail(EXIT_CONFIG, format!("cannot read body file {source}: {e}")))?;
        read_bounded(file, &mut buf, limit)
            .map_err(|e| fail(EXIT_CONFIG, format!("cannot read body file {source}: {e}")))?;
    }
    Ok(Some(buf))
}

/// Read at most `limit` bytes, then stop: an unbounded read of a stuck producer
/// or a `@/dev/zero` slip would eat memory to no purpose. The message names the
/// override, because the bound is ours and the deployment's real cap may differ.
fn read_bounded(source: impl Read, buf: &mut Vec<u8>, limit: usize) -> std::io::Result<()> {
    source.take(limit as u64 + 1).read_to_end(buf)?;
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

pub(crate) async fn run_curl(
    cfg: &Config,
    http: &reqwest::Client,
    args: CurlArgs,
) -> CliResult<()> {
    let target = parse_target(&args.url).map_err(|e| fail(EXIT_CONFIG, e))?;
    let body = read_body(args.data.as_deref(), args.data_raw.as_deref())?;
    let method = match &args.method {
        Some(m) => normalize_method(m).map_err(|e| fail(EXIT_CONFIG, e))?,
        // curl's default: a body implies POST.
        None if body.is_some() => "POST".to_string(),
        None => "GET".to_string(),
    };

    let mut headers = Vec::new();
    for line in &args.headers {
        let (name, value) = parse_header(line).map_err(|e| fail(EXIT_CONFIG, e))?;
        if is_stripped_header(&name) {
            eprintln!(
                "keychute: header {name:?} is not forwarded by the broker (it would let the \
                 caller redirect or re-authenticate the credentialed request); dropping it"
            );
            continue;
        }
        headers.push((name, value));
    }

    let grant_id = match &args.grant_id {
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
            check_grant_covers(cfg, http, id, &target, &method).await?;
            id
        }
        None => {
            let secret_name = args.secret.clone().ok_or_else(|| {
                fail(
                    EXIT_CONFIG,
                    "--secret <name> is required (or --grant-id to reuse an approved grant)",
                )
            })?;
            acquire_grant(cfg, http, &args, &target, &method, secret_name).await?
        }
    };

    proxy_call(cfg, http, &args, &target, &method, headers, body, grant_id).await
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
    if info.revoked {
        return Err(fail(
            crate::EXIT_TIMEOUT,
            format!("grant {grant_id} has been revoked; request a new one"),
        ));
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
    if !info.constraints.path_prefixes.is_empty()
        && !info
            .constraints
            .path_prefixes
            .iter()
            .any(|p| path_covered(p, &target.path))
    {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "grant {grant_id} covers {} but this call is for {}",
                info.constraints.path_prefixes.join(", "),
                target.path
            ),
        ));
    }
    Ok(())
}

/// Prefix match at `/` segment boundaries, mirroring the server's rule:
/// `/v1/account` covers `/v1/account` and `/v1/account/…`, never
/// `/v1/account-delete`.
///
/// A local approximation on the RAW path, deliberately advisory: the server
/// canonicalizes before matching, so a percent-encoded path may match there
/// and not here. Being conservative is the right way round — a false "not
/// covered" costs a clear local error, while a false "covered" just defers to
/// the server's own 403.
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
async fn acquire_grant(
    cfg: &Config,
    http: &reqwest::Client,
    args: &CurlArgs,
    target: &Target,
    method: &str,
    secret_name: String,
) -> CliResult<Uuid> {
    let idem_key = args
        .idempotency_key
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
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

    // Agent-asserted context: the grant block the server parses out of the
    // constraints is what the approval page presents as fact, but the full
    // target — query string included — is what the operator actually reads,
    // and it is forwarded verbatim, so it belongs in front of them.
    let mut structured = build_structured_context().unwrap_or(serde_json::json!({}));
    if let Some(map) = structured.as_object_mut() {
        map.insert(
            "target".to_string(),
            serde_json::Value::String(format!("{method} {}", target.display())),
        );
    }

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
    // Whether the grant can serve a SECOND call is a property of what was
    // granted, not of what was asked for: the approval form lets the operator
    // narrow `max_uses` and `ttl_seconds`, so a request for 5 uses may well
    // have been approved for 1 — and promising reuse then would send the
    // caller after a grant the very next line exhausts. Ask the server.
    //
    // Best-effort: this hint is a convenience, and failing to print it must
    // not fail a call that is otherwise ready to go.
    if args.max_uses != 1 {
        match fetch_grant(cfg, http, grant_id).await {
            Ok(info) => {
                let remaining = info
                    .max_uses
                    .map(|max| max.saturating_sub(info.use_count))
                    // No cap: bounded by the TTL alone.
                    .unwrap_or(u32::MAX);
                // This call spends one of them.
                if remaining > 1 {
                    let budget = match info.max_uses {
                        Some(_) => format!("{} more call(s)", remaining - 1),
                        None => "further calls".to_string(),
                    };
                    eprintln!(
                        "keychute: grant {grant_id} approved until {} — good for {budget}; \
                         reuse it with `--grant-id {grant_id}` (no second approval)",
                        info.not_after.to_rfc3339()
                    );
                } else {
                    eprintln!(
                        "keychute: grant {grant_id} was approved for a single use \
                         (narrowed from the {} requested); this call spends it",
                        args.max_uses
                    );
                }
            }
            Err(e) => eprintln!(
                "keychute: could not read back the granted limits: {}",
                e.message
            ),
        }
    }
    Ok(grant_id)
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
) -> CliResult<()> {
    // Open the destination BEFORE anything leaves: a request that has already
    // been delivered cannot be un-delivered, and reporting only "cannot open
    // /nope/out.json" after a POST has committed upstream invites a retry that
    // repeats the side effect. Truncating a file we then fail to fill is the
    // lesser harm, and is what curl does too.
    let mut sink: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(std::fs::File::create(path).map_err(|e| {
            fail(
                EXIT_CONFIG,
                format!("cannot open --output {}: {e}", path.display()),
            )
        })?),
        None => Box::new(std::io::stdout().lock()),
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
        .bearer_auth(cfg.bearer()?)
        .timeout(Duration::from_secs(args.max_time));
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
    if args.fail && (status.is_client_error() || status.is_server_error()) {
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
        let mut head = format!("HTTP/1.1 {status}\r\n");
        for (name, value) in resp.headers() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(&String::from_utf8_lossy(value.as_bytes()));
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        write_all(&mut sink, head.as_bytes())?;
    }
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        fail(
            EXIT_OTHER,
            format!("reading the upstream response failed: {e}"),
        )
    })? {
        write_all(&mut sink, &chunk)?;
    }
    sink.flush()
        .map_err(|e| fail(EXIT_OTHER, format!("failed flushing the response: {e}")))?;
    if args.output.is_none() && std::io::stdout().is_terminal() {
        // A body without a trailing newline would otherwise run into the
        // shell prompt. Pipes get the bytes verbatim.
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
        let (n, v) = parse_header("Content-Type: application/json").unwrap();
        assert_eq!(n, "content-type");
        assert_eq!(v, "application/json");
        // Only leading whitespace is dropped; the value is otherwise verbatim.
        assert_eq!(parse_header("X-A:  b c ").unwrap().1, "b c ");
        assert!(parse_header("nocolon").is_err());
        assert!(parse_header(": v").is_err());
        assert!(parse_header("Bad Name: v").is_err());
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

    #[test]
    fn body_sources_follow_curls_spelling() {
        assert_eq!(read_body(Some("plain"), None).unwrap().unwrap(), b"plain");
        // --data-raw takes the argument literally, @ and all.
        assert_eq!(
            read_body(None, Some("@literal")).unwrap().unwrap(),
            b"@literal"
        );
        assert_eq!(read_body(None, None).unwrap(), None);
        let dir = std::env::temp_dir().join(format!("keychute-curl-{}", Uuid::new_v4()));
        std::fs::write(&dir, b"from-file").unwrap();
        let path = format!("@{}", dir.display());
        assert_eq!(read_body(Some(&path), None).unwrap().unwrap(), b"from-file");
        std::fs::remove_file(&dir).unwrap();
        assert!(read_body(Some("@/nonexistent/keychute-test"), None).is_err());
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
            read_body_bounded(Some("hello"), None, 4).unwrap().unwrap(),
            b"hello",
            "an inline body is not read through the bounded reader"
        );
        let path = std::env::temp_dir().join(format!("keychute-bound-{}", Uuid::new_v4()));
        std::fs::write(&path, b"0123456789").unwrap();
        let arg = format!("@{}", path.display());
        assert_eq!(
            read_body_bounded(Some(&arg), None, 10).unwrap().unwrap(),
            b"0123456789"
        );
        // ...and over it fails with a message naming the override, since the
        // bound is ours and the deployment's real cap may be higher.
        let err = read_body_bounded(Some(&arg), None, 9).unwrap_err();
        assert!(err.message.contains(MAX_BODY_ENV), "{}", err.message);
        assert_eq!(err.code, EXIT_CONFIG);
        std::fs::remove_file(&path).unwrap();
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
