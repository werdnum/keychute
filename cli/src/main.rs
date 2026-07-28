//! keychute CLI: request secrets from a Keychute server (CUJ 2, tier-2 cli-read).
//!
//! The secret goes to STDOUT and nowhere else; all diagnostics go to stderr.
//!
//! Exit codes: 0 success, 2 usage/config error, 3 denied, 4 timeout/expired
//! (including an expired grant), 5 payload lost, 1 anything else (including a
//! grant whose uses are already exhausted).

mod pipeline;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine as _;
use clap::{Parser, Subcommand};
use keychute_types::{
    ApiError, Constraints, CreateAccessRequest, Mechanism, ReadGrantRequest, ReadGrantResponse,
    RequestContext, RequestState, SecretEncoding,
};
use serde::Deserialize;
use uuid::Uuid;

const EXIT_OTHER: i32 = 1;
const EXIT_CONFIG: i32 = 2;
const EXIT_DENIED: i32 = 3;
const EXIT_TIMEOUT: i32 = 4;
const EXIT_PAYLOAD_LOST: i32 = 5;

/// How long a single long-poll on the wait endpoint asks the server to hold.
const WAIT_POLL_SECONDS: u64 = 60;
/// Slack added on top of the server-side long-poll for the client timeout.
const WAIT_HTTP_SLACK_SECONDS: u64 = 15;
/// Timeout for non-long-poll requests.
const HTTP_TIMEOUT_SECONDS: u64 = 30;
/// Attempts for the grant read (same idempotency key each time).
const READ_ATTEMPTS: u32 = 3;
/// Attempts for the access-request creation (same idempotency key each time,
/// so a retry after a lost response returns the original request rather than
/// minting a duplicate pending request and a duplicate operator push).
const CREATE_ATTEMPTS: u32 = 3;
/// Backoff between creation/read retries.
const RETRY_BACKOFF_SECONDS: u64 = 1;
/// Consecutive network failures tolerated while waiting for approval.
const MAX_WAIT_NETWORK_ERRORS: u32 = 5;

#[derive(Parser)]
#[command(name = "keychute", version, about = "Keychute secret delivery CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Request a secret; once approved, print it to stdout.
    Request(RequestArgs),
    /// Print the state of an access request as JSON (never the secret).
    Status {
        /// The access request id.
        request_id: String,
    },
}

#[derive(clap::Args)]
struct RequestArgs {
    /// Name of the secret to request.
    secret_name: String,
    /// Human-readable reason, shown verbatim on the approval page.
    #[arg(long, default_value = "")]
    reason: String,
    /// Requested grant TTL in seconds.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
    /// Delivery mechanism.
    #[arg(long, default_value = "cli-read")]
    mechanism: String,
    /// How long to wait for approval before giving up, in seconds.
    #[arg(long, default_value_t = 900)]
    timeout: u64,
    /// Idempotency key for the access request (random UUID if omitted).
    #[arg(long)]
    idempotency_key: Option<String>,
    /// Always append a trailing newline to the secret on stdout
    /// (default: only when stdout is a TTY).
    #[arg(long)]
    newline: bool,
}

/// A terminal failure: message for stderr plus the process exit code.
struct Failure {
    code: i32,
    message: String,
}

fn fail(code: i32, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

type CliResult<T> = Result<T, Failure>;

struct Config {
    /// Base URL of the Keychute API (KEYCHUTE_URL).
    url: String,
    /// External/UI base URL used only for the approval hint printed to stderr.
    external_url: String,
    token: Option<String>,
    token_file: Option<PathBuf>,
    ca_bundle: Option<PathBuf>,
}

impl Config {
    fn from_env() -> CliResult<Config> {
        let url = std::env::var("KEYCHUTE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| fail(EXIT_CONFIG, "KEYCHUTE_URL is not set"))?;
        let url = url.trim().trim_end_matches('/').to_string();
        // Every request carries the bearer token, and a successful flow
        // carries the released secret back: plaintext transport is the same
        // exposure the server refuses for non-loopback binds, so refuse it
        // here too unless explicitly opted in.
        let allow_insecure = std::env::var("KEYCHUTE_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        validate_api_url(&url, allow_insecure).map_err(|e| fail(EXIT_CONFIG, e))?;
        let external_url = std::env::var("KEYCHUTE_EXTERNAL_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .unwrap_or_else(|| url.clone());
        let token = std::env::var("KEYCHUTE_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        let token_file = std::env::var("KEYCHUTE_TOKEN_FILE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        if token.is_none() && token_file.is_none() {
            return Err(fail(
                EXIT_CONFIG,
                "no credentials: set KEYCHUTE_TOKEN or KEYCHUTE_TOKEN_FILE",
            ));
        }
        let ca_bundle = std::env::var("KEYCHUTE_CA_BUNDLE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        Ok(Config {
            url,
            external_url,
            token,
            token_file,
            ca_bundle,
        })
    }

    /// Bearer token for one request. The token file is re-read on every call
    /// because projected service-account tokens rotate.
    fn bearer(&self) -> CliResult<String> {
        if let Some(t) = &self.token {
            return Ok(t.clone());
        }
        let path = self.token_file.as_ref().expect("checked in from_env");
        let raw = std::fs::read_to_string(path).map_err(|e| {
            fail(
                EXIT_CONFIG,
                format!("cannot read KEYCHUTE_TOKEN_FILE {}: {e}", path.display()),
            )
        })?;
        let tok = raw.trim();
        if tok.is_empty() {
            return Err(fail(
                EXIT_CONFIG,
                format!("KEYCHUTE_TOKEN_FILE {} is empty", path.display()),
            ));
        }
        Ok(tok.to_string())
    }
}

fn build_http_client(cfg: &Config) -> CliResult<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().user_agent(concat!("keychute-cli/", env!("CARGO_PKG_VERSION")));
    if let Some(path) = &cfg.ca_bundle {
        let pem = std::fs::read(path).map_err(|e| {
            fail(
                EXIT_CONFIG,
                format!("cannot read KEYCHUTE_CA_BUNDLE {}: {e}", path.display()),
            )
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            fail(
                EXIT_CONFIG,
                format!("invalid PEM in KEYCHUTE_CA_BUNDLE {}: {e}", path.display()),
            )
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| fail(EXIT_OTHER, format!("failed to build HTTP client: {e}")))
}

/// Lenient view of the server's access-request status responses: the create
/// response may omit fields (`expires_at`) that the full status object carries.
#[derive(Debug, Deserialize)]
struct StatusResponse {
    request_id: Uuid,
    state: RequestState,
    #[serde(default)]
    grant_id: Option<Uuid>,
    #[serde(default)]
    deny_reason: Option<String>,
}

/// Derive the grant-read idempotency key from the request's idempotency key.
/// Stable across retries so a lost response replays (IMPLEMENTATION addendum #6).
fn read_idempotency_key(request_key: &str) -> String {
    format!("cli-{request_key}")
}

/// The server caps request idempotency keys at 128 bytes and read keys at
/// 160; capping the request key at 124 keeps the derived `cli-` read key
/// safely under both. Checked up front so the failure is a clear usage error.
const MAX_REQUEST_IDEM_KEY_BYTES: usize = 124;

fn validate_idempotency_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("idempotency key must not be empty".into());
    }
    if key.len() > MAX_REQUEST_IDEM_KEY_BYTES {
        return Err(format!(
            "idempotency key too long ({} bytes; max {MAX_REQUEST_IDEM_KEY_BYTES})",
            key.len()
        ));
    }
    Ok(())
}

/// Refuse a plaintext API URL that would send the bearer token and the
/// released secret over the network. `http://` is allowed only for loopback
/// hosts (local development) or with the explicit `KEYCHUTE_INSECURE_HTTP`
/// opt-in — mirroring the server's own non-loopback plaintext refusal.
fn validate_api_url(url: &str, allow_insecure: bool) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| format!("invalid KEYCHUTE_URL {url:?}: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match parsed.host_str() {
                Some(h) => {
                    // IPv6 hosts serialize bracketed ("[::1]").
                    let bare = h.trim_start_matches('[').trim_end_matches(']');
                    bare.eq_ignore_ascii_case("localhost")
                        || bare
                            .parse::<std::net::IpAddr>()
                            .map(|ip| ip.is_loopback())
                            .unwrap_or(false)
                }
                None => false,
            };
            if loopback || allow_insecure {
                Ok(())
            } else {
                Err(format!(
                    "refusing plaintext http:// KEYCHUTE_URL to non-loopback host {:?}: \
                     the bearer token and released secret would travel unencrypted. \
                     Use https://, or set KEYCHUTE_INSECURE_HTTP=1 to override",
                    parsed.host_str().unwrap_or("")
                ))
            }
        }
        other => Err(format!(
            "unsupported KEYCHUTE_URL scheme {other:?}: use https:// (or http:// for loopback)"
        )),
    }
}

/// Assemble agent-asserted structured context: best-effort pipeline capture
/// plus $KEYCHUTE_CONTEXT verbatim under `extra`.
fn build_structured_context() -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    if let Some(captured) = pipeline::capture() {
        // Agent-asserted: ancestor chain plus same-shell pipeline peers.
        map.insert(
            "pipeline".to_string(),
            serde_json::json!(captured.ancestors),
        );
        if !captured.siblings.is_empty() {
            map.insert(
                "pipeline_siblings".to_string(),
                serde_json::json!(captured.siblings),
            );
        }
    }
    if let Ok(extra) = std::env::var("KEYCHUTE_CONTEXT") {
        map.insert("extra".to_string(), serde_json::Value::String(extra));
    }
    if map.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(map))
    }
}

/// Extract a human-readable message from an error response body.
fn api_error_message(status: reqwest::StatusCode, body: &str) -> String {
    match serde_json::from_str::<ApiError>(body) {
        Ok(err) => format!("{} ({})", err.error.message, err.error.code),
        Err(_) => format!("server returned {status}"),
    }
}

/// Classify an HTTP 410 from the grant-read endpoint. The server uses 410 for
/// three distinct, differently-remediable conditions (server/src/api/error.rs):
///
/// - `payload-lost`: the plaintext is gone because the process restarted under
///   the ephemeral KEK. Nothing was released; ask for re-approval. Exit 5.
/// - `grant-expired`: the grant is revoked or past `not_after`. That is the
///   documented timeout/expired condition. Exit 4.
/// - `grant-exhausted`: the grant's uses are spent — the secret was already
///   released (outside the replay window, or to an earlier invocation). This is
///   neither a timeout nor a payload loss, and blindly re-requesting would burn
///   operator attention on a duplicate approval, so it gets the generic code so
///   callers surface it instead of treating it as "just ask again". Exit 1.
///
/// An unknown or unparseable 410 body also gets the generic code.
fn classify_gone(body: &str) -> Failure {
    let code = serde_json::from_str::<ApiError>(body)
        .ok()
        .map(|e| e.error.code);
    match code.as_deref() {
        Some("payload-lost") => fail(
            EXIT_PAYLOAD_LOST,
            "the grant's payload was lost (server restarted before the read); \
             submit a new request for re-approval",
        ),
        Some("grant-expired") => fail(
            EXIT_TIMEOUT,
            "the grant has expired or was revoked before the read; \
             submit a new request for re-approval",
        ),
        Some("grant-exhausted") => fail(
            EXIT_OTHER,
            "the grant has no uses remaining (the secret was already released); \
             submit a new request if you need it again",
        ),
        _ => fail(
            EXIT_OTHER,
            format!(
                "grant is no longer usable: {}",
                api_error_message(reqwest::StatusCode::GONE, body)
            ),
        ),
    }
}

async fn run_request(cfg: &Config, http: &reqwest::Client, args: RequestArgs) -> CliResult<()> {
    let RequestArgs {
        secret_name,
        reason,
        ttl,
        mechanism,
        timeout,
        idempotency_key,
        newline,
    } = args;
    let mechanism = Mechanism::from_str_opt(&mechanism)
        .ok_or_else(|| fail(EXIT_CONFIG, format!("unknown mechanism {mechanism:?}")))?;
    if !mechanism.is_releasing() {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "mechanism {} is not readable via the CLI (no plaintext release)",
                mechanism.as_str()
            ),
        ));
    }
    let idem_key = idempotency_key.unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_idempotency_key(&idem_key).map_err(|e| fail(EXIT_CONFIG, e))?;

    let body = CreateAccessRequest {
        idempotency_key: idem_key.clone(),
        secret_name,
        mechanism,
        constraints: Constraints {
            ttl_seconds: ttl,
            max_uses: Some(1),
            ..Constraints::default()
        },
        context: RequestContext {
            reason,
            structured: build_structured_context(),
        },
    };

    let deadline = Instant::now() + Duration::from_secs(timeout);

    // Create the access request.
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
            return Err(fail(EXIT_TIMEOUT, "request expired before approval"));
        }
        RequestState::Pending => {
            return Err(fail(
                EXIT_TIMEOUT,
                format!("timed out after {timeout}s waiting for approval"),
            ));
        }
    }
    let grant_id = st.grant_id.ok_or_else(|| {
        fail(
            EXIT_OTHER,
            "server reported approval but returned no grant id",
        )
    })?;

    let released = read_grant(cfg, http, grant_id, &read_idempotency_key(&idem_key)).await?;
    write_secret(&released, newline)
}

/// Create the access request, retrying transient failures with the SAME
/// idempotency key.
///
/// If the server commits the request but the response is lost in flight, a
/// retry with the same key returns the original request (IMPLEMENTATION
/// addendum #18: same key + same canonical body → the original; a different
/// body under the same key → 409). Without the retry, the CLI would exit and a
/// rerun without `--idempotency-key` would mint a fresh UUID, duplicating both
/// the pending request and the operator push.
///
/// Retry discipline mirrors `read_grant`: transport errors, unreadable bodies
/// and 5xx retry; a fully parsed 4xx is definitive.
async fn create_access_request(
    cfg: &Config,
    http: &reqwest::Client,
    body: &CreateAccessRequest,
) -> CliResult<StatusResponse> {
    let mut last_err = String::new();
    for attempt in 1..=CREATE_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(RETRY_BACKOFF_SECONDS)).await;
        }
        // One attempt end-to-end; Err(msg) means "transient, retry".
        let attempt_result: Result<CliResult<StatusResponse>, String> = async {
            let bearer = match cfg.bearer() {
                Ok(b) => b,
                // Config errors are definitive, not transient.
                Err(f) => return Ok(Err(f)),
            };
            let resp = http
                .post(format!("{}/v1/access-requests", cfg.url))
                .bearer_auth(bearer)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
                .json(body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("failed reading server response: {e}"))?;
            if status.is_client_error() {
                // Definitive, fully parsed 4xx: retrying cannot change it.
                let msg = api_error_message(status, &text);
                let code = match status.as_u16() {
                    401 => EXIT_CONFIG,
                    403 => EXIT_DENIED,
                    _ => EXIT_OTHER,
                };
                return Ok(Err(fail(code, format!("access request rejected: {msg}"))));
            }
            if !status.is_success() {
                // 5xx and everything else: transient, retry (same idem key).
                return Err(format!(
                    "access request rejected: {}",
                    api_error_message(status, &text)
                ));
            }
            match serde_json::from_str::<StatusResponse>(&text) {
                Ok(st) => Ok(Ok(st)),
                // Truncated/garbled success body: the retry replays the create.
                Err(e) => Err(format!("unexpected create response from server: {e}")),
            }
        }
        .await;
        match attempt_result {
            Ok(done) => return done,
            Err(msg) => {
                eprintln!(
                    "keychute: request creation attempt {attempt}/{CREATE_ATTEMPTS} failed: {msg}"
                );
                last_err = msg;
            }
        }
    }
    Err(fail(
        EXIT_OTHER,
        format!("request creation failed after {CREATE_ATTEMPTS} attempts: {last_err}"),
    ))
}

/// Long-poll the wait endpoint until the request resolves or `deadline` passes.
async fn wait_for_resolution(
    cfg: &Config,
    http: &reqwest::Client,
    request_id: Uuid,
    deadline: Instant,
) -> CliResult<StatusResponse> {
    let mut network_errors: u32 = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(fail(
                EXIT_TIMEOUT,
                "timed out waiting for approval (request may still be pending server-side)",
            ));
        }
        let poll = WAIT_POLL_SECONDS.min(remaining.as_secs().max(1));
        let resp = http
            .get(format!(
                "{}/v1/access-requests/{}/wait?timeout_seconds={}",
                cfg.url, request_id, poll
            ))
            .bearer_auth(cfg.bearer()?)
            .timeout(Duration::from_secs(poll + WAIT_HTTP_SLACK_SECONDS))
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                network_errors += 1;
                if network_errors >= MAX_WAIT_NETWORK_ERRORS {
                    return Err(fail(EXIT_OTHER, format!("wait failed repeatedly: {e}")));
                }
                eprintln!("keychute: transient error while waiting, retrying: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let status = resp.status();
        // Body read and parse failures are the same transient class as a
        // failed send (connection dropped mid-response, truncated body): they
        // share the retry budget instead of abandoning a still-pending
        // request. Only a fully read response resets the counter.
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                network_errors += 1;
                if network_errors >= MAX_WAIT_NETWORK_ERRORS {
                    return Err(fail(
                        EXIT_OTHER,
                        format!("wait failed repeatedly: failed reading wait response: {e}"),
                    ));
                }
                eprintln!("keychute: transient error while waiting, retrying: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        if !status.is_success() {
            return Err(fail(
                EXIT_OTHER,
                format!("wait failed: {}", api_error_message(status, &text)),
            ));
        }
        let st: StatusResponse = match serde_json::from_str(&text) {
            Ok(st) => st,
            Err(e) => {
                network_errors += 1;
                if network_errors >= MAX_WAIT_NETWORK_ERRORS {
                    return Err(fail(
                        EXIT_OTHER,
                        format!("wait failed repeatedly: unexpected wait response: {e}"),
                    ));
                }
                eprintln!("keychute: unexpected wait response, retrying: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        network_errors = 0;
        if st.state != RequestState::Pending {
            return Ok(st);
        }
    }
}

/// Exercise the grant's single logical read. The idempotency key is stable
/// across retries so a lost response replays instead of burning a second use.
///
/// The ENTIRE attempt (send + status + body read + parse) is inside the retry
/// loop: a truncated or unreadable body retries with the same key and replays
/// server-side. Only a fully parsed, definitive 4xx (including 410) stops the
/// retries.
async fn read_grant(
    cfg: &Config,
    http: &reqwest::Client,
    grant_id: Uuid,
    idem_key: &str,
) -> CliResult<ReadGrantResponse> {
    let body = ReadGrantRequest {
        idempotency_key: idem_key.to_string(),
    };
    let mut last_err = String::new();
    for attempt in 1..=READ_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_secs(RETRY_BACKOFF_SECONDS)).await;
        }
        // One attempt end-to-end; Err(msg) means "transient, retry".
        let attempt_result: Result<CliResult<ReadGrantResponse>, String> = async {
            let bearer = match cfg.bearer() {
                Ok(b) => b,
                // Config errors are definitive, not transient.
                Err(f) => return Ok(Err(f)),
            };
            let resp = http
                .post(format!("{}/v1/grants/{}/read", cfg.url, grant_id))
                .bearer_auth(bearer)
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| format!("failed reading response body: {e}"))?;
            if status == reqwest::StatusCode::GONE {
                return Ok(Err(classify_gone(&text)));
            }
            if status.is_client_error() {
                // Definitive, fully parsed 4xx: retrying cannot change it.
                return Ok(Err(fail(
                    EXIT_OTHER,
                    format!("grant read failed: {}", api_error_message(status, &text)),
                )));
            }
            if !status.is_success() {
                // 5xx and everything else: transient, retry (same idem key).
                return Err(format!(
                    "grant read failed: {}",
                    api_error_message(status, &text)
                ));
            }
            match serde_json::from_str::<ReadGrantResponse>(&text) {
                Ok(released) => Ok(Ok(released)),
                // Truncated/garbled success body: retry replays the release.
                Err(e) => Err(format!("unexpected read response from server: {e}")),
            }
        }
        .await;
        match attempt_result {
            Ok(done) => return done,
            Err(msg) => {
                eprintln!("keychute: grant read attempt {attempt}/{READ_ATTEMPTS} failed: {msg}");
                last_err = msg;
            }
        }
    }
    Err(fail(
        EXIT_OTHER,
        format!("grant read failed after {READ_ATTEMPTS} attempts: {last_err}"),
    ))
}

/// Write the secret bytes to stdout. Nothing about the payload is ever logged.
fn write_secret(released: &ReadGrantResponse, force_newline: bool) -> CliResult<()> {
    let bytes: Vec<u8> = match released.encoding {
        SecretEncoding::Utf8 => released.secret.as_bytes().to_vec(),
        SecretEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(&released.secret)
            .map_err(|_| fail(EXIT_OTHER, "server sent invalid base64 payload"))?,
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(&bytes)
        .map_err(|e| fail(EXIT_OTHER, format!("failed writing secret to stdout: {e}")))?;
    if force_newline || stdout.is_terminal() {
        out.write_all(b"\n")
            .map_err(|e| fail(EXIT_OTHER, format!("failed writing to stdout: {e}")))?;
    }
    out.flush()
        .map_err(|e| fail(EXIT_OTHER, format!("failed flushing stdout: {e}")))?;
    Ok(())
}

async fn run_status(cfg: &Config, http: &reqwest::Client, request_id: &str) -> CliResult<()> {
    let id: Uuid = request_id
        .parse()
        .map_err(|_| fail(EXIT_CONFIG, format!("invalid request id {request_id:?}")))?;
    let resp = http
        .get(format!("{}/v1/access-requests/{}", cfg.url, id))
        .bearer_auth(cfg.bearer()?)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|e| fail(EXIT_OTHER, format!("status request failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| fail(EXIT_OTHER, format!("failed reading status response: {e}")))?;
    if !status.is_success() {
        return Err(fail(
            EXIT_OTHER,
            format!("status failed: {}", api_error_message(status, &text)),
        ));
    }
    println!("{}", text.trim_end());
    Ok(())
}

async fn run(cli: Cli) -> CliResult<()> {
    let cfg = Config::from_env()?;
    let http = build_http_client(&cfg)?;
    match cli.cmd {
        Cmd::Request(args) => run_request(&cfg, &http, args).await,
        Cmd::Status { request_id } => run_status(&cfg, &http, &request_id).await,
    }
}

#[tokio::main]
async fn main() {
    // clap exits with code 2 on usage errors, matching our config-error code.
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(()) => 0,
        Err(f) => {
            eprintln!("keychute: {}", f.message);
            f.code
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn api_url_plaintext_rules() {
        // https anywhere.
        assert!(validate_api_url("https://keychute.example.dev", false).is_ok());
        // http only on loopback.
        assert!(validate_api_url("http://127.0.0.1:8080", false).is_ok());
        assert!(validate_api_url("http://[::1]:8080", false).is_ok());
        assert!(validate_api_url("http://localhost:8080", false).is_ok());
        // Non-loopback plaintext leaks the bearer token and secret.
        assert!(validate_api_url("http://keychute.example.dev", false).is_err());
        assert!(validate_api_url("http://10.0.0.5:8080", false).is_err());
        // ...unless explicitly opted in.
        assert!(validate_api_url("http://10.0.0.5:8080", true).is_ok());
        // Garbage and non-http schemes are config errors.
        assert!(validate_api_url("not a url", false).is_err());
        assert!(validate_api_url("ftp://keychute.example.dev", false).is_err());
    }

    #[test]
    fn request_arg_defaults() {
        let cli = Cli::parse_from(["keychute", "request", "my-key"]);
        match cli.cmd {
            Cmd::Request(args) => {
                assert_eq!(args.secret_name, "my-key");
                assert_eq!(args.reason, "");
                assert_eq!(args.ttl, 3600);
                assert_eq!(args.mechanism, "cli-read");
                assert_eq!(args.timeout, 900);
                assert_eq!(args.idempotency_key, None);
                assert!(!args.newline);
            }
            _ => panic!("expected request subcommand"),
        }
    }

    #[test]
    fn request_arg_overrides() {
        let cli = Cli::parse_from([
            "keychute",
            "request",
            "my-key",
            "--reason",
            "seal into ns",
            "--ttl",
            "60",
            "--mechanism",
            "direct-read",
            "--timeout",
            "30",
            "--idempotency-key",
            "k1",
            "--newline",
        ]);
        match cli.cmd {
            Cmd::Request(args) => {
                assert_eq!(args.reason, "seal into ns");
                assert_eq!(args.ttl, 60);
                assert_eq!(args.mechanism, "direct-read");
                assert_eq!(args.timeout, 30);
                assert_eq!(args.idempotency_key.as_deref(), Some("k1"));
                assert!(args.newline);
            }
            _ => panic!("expected request subcommand"),
        }
    }

    #[test]
    fn status_args_parse() {
        let cli = Cli::parse_from(["keychute", "status", "9f7f4f6e-0000-0000-0000-000000000000"]);
        match cli.cmd {
            Cmd::Status { request_id } => {
                assert_eq!(request_id, "9f7f4f6e-0000-0000-0000-000000000000");
            }
            _ => panic!("expected status subcommand"),
        }
    }

    #[test]
    fn missing_secret_name_is_usage_error() {
        assert!(Cli::try_parse_from(["keychute", "request"]).is_err());
    }

    #[test]
    fn read_idempotency_key_is_stable_and_derived() {
        let k1 = read_idempotency_key("abc-123");
        let k2 = read_idempotency_key("abc-123");
        assert_eq!(k1, "cli-abc-123");
        assert_eq!(k1, k2);
        assert_ne!(read_idempotency_key("other"), k1);
    }

    #[test]
    fn idempotency_key_length_is_capped_below_server_limits() {
        assert!(validate_idempotency_key(&"k".repeat(124)).is_ok());
        assert!(validate_idempotency_key(&"k".repeat(125)).is_err());
        assert!(validate_idempotency_key("").is_err());
        // Generated keys (UUID, 36 bytes) are always valid, and the derived
        // read key never exceeds the read endpoint's cap.
        let uuid_key = Uuid::new_v4().to_string();
        assert!(validate_idempotency_key(&uuid_key).is_ok());
        assert!(read_idempotency_key(&"k".repeat(124)).len() <= 160);
    }

    #[test]
    fn api_error_message_parses_envelope() {
        let body = r#"{"error":{"code":"policy-deny","message":"nope"}}"#;
        let msg = api_error_message(reqwest::StatusCode::FORBIDDEN, body);
        assert_eq!(msg, "nope (policy-deny)");
        let msg = api_error_message(reqwest::StatusCode::BAD_GATEWAY, "not json");
        assert!(msg.contains("502"));
    }

    fn gone_body(code: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"m"}}}}"#)
    }

    #[test]
    fn gone_codes_map_to_distinct_exit_codes() {
        let lost = classify_gone(&gone_body("payload-lost"));
        assert_eq!(lost.code, EXIT_PAYLOAD_LOST);
        assert!(
            lost.message.contains("payload was lost"),
            "{}",
            lost.message
        );

        let expired = classify_gone(&gone_body("grant-expired"));
        assert_eq!(expired.code, EXIT_TIMEOUT);
        assert!(expired.message.contains("expired"), "{}", expired.message);

        let exhausted = classify_gone(&gone_body("grant-exhausted"));
        assert_eq!(exhausted.code, EXIT_OTHER);
        assert!(
            exhausted.message.contains("no uses remaining"),
            "{}",
            exhausted.message
        );
    }

    #[test]
    fn unknown_or_unparseable_gone_is_generic() {
        let unknown = classify_gone(&gone_body("something-else"));
        assert_eq!(unknown.code, EXIT_OTHER);
        assert!(unknown.message.contains("something-else"));
        let garbage = classify_gone("not json at all");
        assert_eq!(garbage.code, EXIT_OTHER);
        assert!(garbage.message.contains("410"), "{}", garbage.message);
    }
}
