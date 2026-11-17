//! `keychute ssh` — run OpenSSH `ssh` using a private key stored in Keychute
//! (CUJ 2c, tier-2 `cli-read`) without ever writing key bytes to stdout or disk.
//!
//! Flow: validate all arguments and resolve OpenSSH binaries up front, request
//! a single-use `cli-read` grant (with the target session attached as
//! agent-asserted context), load the released private key over stdin into an
//! isolated ephemeral `ssh-agent` whose Unix socket lives in a `0700`
//! temporary directory, run `ssh` against that agent with user/system config
//! bypassed and agent forwarding disabled, then tear down `ssh-agent` and the
//! socket directory before propagating `ssh`'s exit code.
//!
//! # Scope: ssh-SHAPED, not an ssh
//!
//! Only the flags defined here are accepted; unknown options fail at the
//! parser before any approval push is sent.

use std::io::Write;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use base64::Engine as _;
use keychute_types::{
    Constraints, CreateAccessRequest, Mechanism, RequestContext, RequestState, SecretEncoding,
};
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    build_structured_context, create_access_request, fail, read_grant, read_idempotency_key,
    report_resolution, shed_structured_to_fit, wait_for_resolution, CliResult, Config, EXIT_CONFIG,
    EXIT_DENIED, EXIT_OTHER, EXIT_TIMEOUT, MAX_STRUCTURED_BYTES,
};

const MAX_TTL_SECONDS: u64 = 30 * 24 * 3600;
const MAX_APPROVAL_WAIT_SECONDS: u64 = MAX_TTL_SECONDS;
const MAX_SECRET_NAME_BYTES: usize = 256;
const MAX_REASON_BYTES: usize = 4 * 1024;
/// 32 hex chars of SHA-256 + `-` separator, leaving 91 bytes for caller keys
/// under the shared 124-byte `validate_idempotency_key` cap.
const CALL_BINDING_HEX_CHARS: usize = 32;
pub(crate) const MAX_SSH_USER_KEY_BYTES: usize = 124 - (CALL_BINDING_HEX_CHARS + 1);
/// Conservative Unix domain socket path bound (macOS/Linux `sun_path` is 104/108
/// bytes; leave margin for NUL and directory suffix).
const MAX_SOCKET_PATH_BYTES: usize = 100;
const AGENT_READY_POLL_ATTEMPTS: usize = 500;
const AGENT_READY_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Bounded lifetime (`ssh-agent -t` / `ssh-add -t`) so even an uncatchable
/// `SIGKILL` cannot leave a decrypted private key resident in an orphaned
/// `ssh-agent` indefinitely. `ForwardAgent=no` is hardcoded, so the agent is
/// only consulted during initial connection authentication.
const MIN_AGENT_KEY_LIFETIME_SECONDS: u64 = 60;
const MAX_AGENT_KEY_LIFETIME_SECONDS: u64 = 300;
const AGENT_HANDSHAKE_GRACE_SECONDS: u64 = 30;

fn agent_key_lifetime_seconds(connect_timeout: Option<u64>) -> u64 {
    match connect_timeout {
        Some(ct) => ct.saturating_add(AGENT_HANDSHAKE_GRACE_SECONDS).clamp(
            MIN_AGENT_KEY_LIFETIME_SECONDS,
            MAX_AGENT_KEY_LIFETIME_SECONDS,
        ),
        None => MIN_AGENT_KEY_LIFETIME_SECONDS,
    }
}

#[cfg(unix)]
struct UnixSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl UnixSignals {
    fn register() -> CliResult<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        let sigint = signal(SignalKind::interrupt())
            .map_err(|e| fail(EXIT_OTHER, format!("failed installing SIGINT handler: {e}")))?;
        let sigterm = signal(SignalKind::terminate()).map_err(|e| {
            fail(
                EXIT_OTHER,
                format!("failed installing SIGTERM handler: {e}"),
            )
        })?;
        let sighup = signal(SignalKind::hangup())
            .map_err(|e| fail(EXIT_OTHER, format!("failed installing SIGHUP handler: {e}")))?;
        Ok(UnixSignals {
            sigint,
            sigterm,
            sighup,
        })
    }
}

#[derive(clap::Args)]
pub(crate) struct SshArgs {
    /// SSH destination (`[user@]host`).
    pub destination: String,
    /// Name of the Keychute secret holding the SSH private key. If you do not
    /// know the exact name, pick a plausible one (e.g. `node-ssh-key`): when
    /// nothing is stored under it, the approver can release the right stored
    /// secret instead.
    #[arg(long)]
    pub secret: String,
    /// Human-readable reason, shown verbatim on the approval page.
    #[arg(long, default_value = "")]
    pub reason: String,
    /// Requested grant TTL in seconds.
    #[arg(long, default_value_t = 300)]
    pub ttl: u64,
    /// How long to wait for approval before giving up, in seconds.
    #[arg(long, default_value_t = 900)]
    pub timeout: u64,
    /// Idempotency key for the access request (random UUID if omitted).
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Login username on the remote host (cannot be combined with `user@host`).
    #[arg(short = 'l', long = "login-name", value_name = "USER")]
    pub login_name: Option<String>,
    /// Remote SSH port (`-p`).
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: Option<u16>,
    /// Force pseudo-terminal allocation (`-t`; pass twice `-tt` to force even
    /// without a local TTY).
    #[arg(short = 't', action = clap::ArgAction::Count)]
    pub force_tty: u8,
    /// Disable pseudo-terminal allocation (`-T`).
    #[arg(short = 'T', conflicts_with = "force_tty")]
    pub disable_tty: bool,
    /// Do not execute a remote command (`-N`, useful with `-L`).
    #[arg(short = 'N', conflicts_with = "command")]
    pub no_remote_command: bool,
    /// Local port forwarding (`-L [bind_address:]port:host:hostport`, repeatable).
    #[arg(short = 'L', value_name = "SPEC")]
    pub local_forwards: Vec<String>,
    /// Force IPv4 addresses only (`-4`).
    #[arg(short = '4')]
    pub ipv4: bool,
    /// Force IPv6 addresses only (`-6`).
    #[arg(short = '6', conflicts_with = "ipv4")]
    pub ipv6: bool,
    /// Quiet mode (`-q`).
    #[arg(short = 'q', long)]
    pub quiet: bool,
    /// Verbose mode (`-v`, repeatable up to `-vvv`).
    #[arg(short = 'v', long, action = clap::ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,
    /// SSH connection timeout in seconds (`-o ConnectTimeout=N`).
    #[arg(long, value_name = "SECONDS")]
    pub connect_timeout: Option<u64>,
    /// StrictHostKeyChecking policy: `accept-new` (default) or `yes`.
    #[arg(long, default_value = "accept-new", value_name = "MODE")]
    pub strict_host_key_checking: String,
    /// Custom known_hosts file (`-o UserKnownHostsFile=PATH`). Refuses `/dev/null`.
    #[arg(long, value_name = "PATH")]
    pub known_hosts_file: Option<PathBuf>,
    /// Optional remote command and arguments. Pass `--` before the command if
    /// it includes flags starting with `-` (or pass a single quoted string).
    #[arg(value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDestination {
    inline_user: Option<String>,
    host: String,
}

impl ParsedDestination {
    fn ssh_target_arg(&self) -> String {
        match &self.inline_user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }

    fn effective_user<'a>(&'a self, login_name: Option<&'a str>) -> Option<&'a str> {
        self.inline_user.as_deref().or(login_name)
    }

    fn display_target(&self, login_name: Option<&str>) -> String {
        match self.effective_user(login_name) {
            Some(user) => {
                if self.host.contains(':') {
                    format!("{user}@[{}]", self.host)
                } else {
                    format!("{user}@{}", self.host)
                }
            }
            None => {
                if self.host.contains(':') {
                    format!("[{}]", self.host)
                } else {
                    self.host.clone()
                }
            }
        }
    }
}

struct OpenSshBins {
    ssh: PathBuf,
    ssh_agent: PathBuf,
    ssh_add: PathBuf,
}

/// Ensures the ephemeral `ssh-agent` process and its socket directory are
/// cleaned up on every exit path, including early errors or panics.
struct AgentGuard {
    dir: PathBuf,
    child: Option<tokio::process::Child>,
}

impl AgentGuard {
    fn new(dir: PathBuf) -> Self {
        AgentGuard { dir, child: None }
    }

    async fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = child.try_wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(crate) async fn run_ssh(cfg: &Config, http: &reqwest::Client, args: SshArgs) -> CliResult<()> {
    let parsed = parse_destination(&args.destination).map_err(|e| fail(EXIT_CONFIG, e))?;
    validate_options(&args, &parsed)?;
    let bins = resolve_openssh_bins()?;
    let structured = build_ssh_context(&parsed, &args)?;

    let user_key = args
        .idempotency_key
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let idem_key = call_bound_idempotency_key(&user_key, &parsed, &args);

    let body = CreateAccessRequest {
        idempotency_key: idem_key.clone(),
        secret_name: args.secret.clone(),
        mechanism: Mechanism::CliRead,
        constraints: Constraints {
            ttl_seconds: args.ttl,
            max_uses: Some(1),
            ..Constraints::default()
        },
        context: RequestContext {
            reason: args.reason.clone(),
            structured: Some(structured),
        },
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(args.timeout);
    let mut st = create_access_request(cfg, http, &body).await?;
    let requested_secret = body.secret_name;

    if st.state == RequestState::Pending {
        eprintln!(
            "Waiting for approval: {}/ui/requests/{}",
            cfg.external_url, st.request_id
        );
        st = wait_for_resolution(cfg, http, st.request_id, deadline).await?;
    }

    match st.state {
        RequestState::Approved => report_resolution(&requested_secret, &st),
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
                format!("timed out after {}s waiting for approval", args.timeout),
            ));
        }
    }
    let grant_id = st.grant_id.ok_or_else(|| {
        fail(
            EXIT_OTHER,
            "server reported approval but returned no grant id",
        )
    })?;

    let mut released = read_grant(cfg, http, grant_id, &read_idempotency_key(&idem_key)).await?;
    let mut key_bytes = decode_and_normalize_key(&mut released)?;

    #[cfg(unix)]
    let mut signals = UnixSignals::register()?;
    let key_lifetime_secs = agent_key_lifetime_seconds(args.connect_timeout);

    let mut guard = start_ephemeral_agent(&bins, key_lifetime_secs).await?;
    let sock = guard.dir.join("s");

    enum LoadOutcome {
        Finished(CliResult<()>),
        Signal(i32),
    }

    #[cfg(unix)]
    let load_outcome = tokio::select! {
        res = load_key_into_agent(&bins, &sock, &mut key_bytes, key_lifetime_secs) => LoadOutcome::Finished(res),
        _ = signals.sigint.recv() => LoadOutcome::Signal(130),
        _ = signals.sigterm.recv() => LoadOutcome::Signal(143),
        _ = signals.sighup.recv() => LoadOutcome::Signal(129),
    };
    #[cfg(not(unix))]
    let load_outcome = LoadOutcome::Finished(
        load_key_into_agent(&bins, &sock, &mut key_bytes, key_lifetime_secs).await,
    );

    key_bytes.zeroize();
    match load_outcome {
        LoadOutcome::Signal(code) => {
            guard.shutdown().await;
            return Err(crate::silent_exit(code));
        }
        LoadOutcome::Finished(Err(err)) => {
            guard.shutdown().await;
            return Err(err);
        }
        LoadOutcome::Finished(Ok(())) => {}
    }

    #[cfg(unix)]
    let ssh_res = run_ssh_child(&bins, &sock, &parsed, &args, &mut guard, &mut signals).await;
    #[cfg(not(unix))]
    let ssh_res = run_ssh_child(&bins, &sock, &parsed, &args, &mut guard).await;
    guard.shutdown().await;
    let status = ssh_res?;
    if status.success() {
        return Ok(());
    }
    Err(crate::silent_exit(exit_code_from_status(status)))
}

fn parse_destination(raw: &str) -> Result<ParsedDestination, String> {
    if raw.is_empty() {
        return Err("destination must not be empty".into());
    }
    if raw
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace() || c == '\u{7f}')
    {
        return Err(format!(
            "refusing destination {raw:?}: control characters and whitespace are not allowed"
        ));
    }
    if raw.starts_with("ssh://") {
        return Err(format!(
            "ssh:// URI {raw:?} is not supported here: pass `[user@]host` and `-p <port>` instead"
        ));
    }
    if raw.starts_with('-') {
        return Err(format!("destination {raw:?} must not begin with '-'"));
    }
    if raw.contains('/') || raw.contains('\\') || raw.contains('?') || raw.contains('#') {
        return Err(format!(
            "invalid destination {raw:?}: expected `[user@]host`"
        ));
    }

    let (inline_user, raw_host) = match raw.split_once('@') {
        Some((user, host)) => {
            if user.is_empty() {
                return Err(format!("empty username before '@' in destination {raw:?}"));
            }
            if host.is_empty() {
                return Err(format!("empty host after '@' in destination {raw:?}"));
            }
            if host.contains('@') {
                return Err(format!("multiple '@' characters in destination {raw:?}"));
            }
            if user.starts_with('-') {
                return Err(format!("username {user:?} must not begin with '-'"));
            }
            if host.starts_with('-') {
                return Err(format!("host {host:?} must not begin with '-'"));
            }
            (Some(user.to_string()), host)
        }
        None => (None, raw),
    };

    let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
        let inner = &raw_host[1..raw_host.len() - 1];
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(format!(
                "invalid bracketed IPv6 address in destination {raw:?}"
            ));
        }
        inner.to_string()
    } else if raw_host.contains('[') || raw_host.contains(']') {
        return Err(format!("invalid brackets in destination {raw:?}"));
    } else if raw_host.contains(':') {
        if raw_host.parse::<Ipv6Addr>().is_ok() {
            raw_host.to_string()
        } else {
            return Err(format!(
                "destination {raw:?} appears to include ':port'; pass `[user@]host` and `-p <port>` instead"
            ));
        }
    } else {
        raw_host.to_string()
    };

    Ok(ParsedDestination { inline_user, host })
}

fn validate_options(args: &SshArgs, parsed: &ParsedDestination) -> CliResult<()> {
    if args.secret.is_empty() || args.secret.len() > MAX_SECRET_NAME_BYTES {
        return Err(fail(
            EXIT_CONFIG,
            format!("--secret must be 1 to {MAX_SECRET_NAME_BYTES} bytes"),
        ));
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
    if args.ttl < 1 || args.ttl > MAX_TTL_SECONDS {
        return Err(fail(
            EXIT_CONFIG,
            format!("--ttl must be between 1 second and 30 days ({MAX_TTL_SECONDS} seconds)"),
        ));
    }
    if args.timeout > MAX_APPROVAL_WAIT_SECONDS {
        return Err(fail(
            EXIT_CONFIG,
            format!("--timeout must be at most {MAX_APPROVAL_WAIT_SECONDS} seconds (30 days)"),
        ));
    }
    if let Some(key) = &args.idempotency_key {
        if key.is_empty() {
            return Err(fail(
                EXIT_CONFIG,
                "--idempotency-key is empty; omit it for a random key, or pass a real one",
            ));
        }
        if key.len() > MAX_SSH_USER_KEY_BYTES {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "--idempotency-key too long ({} bytes; max {MAX_SSH_USER_KEY_BYTES} here, \
                     because the session parameters are bound into the key sent to the server)",
                    key.len()
                ),
            ));
        }
    }
    if let Some(user) = &args.login_name {
        if parsed.inline_user.is_some() {
            return Err(fail(
                EXIT_CONFIG,
                "cannot combine `-l/--login-name` with `user@host` in destination",
            ));
        }
        validate_simple_token("-l/--login-name", user, &['@', '/', '\\'])?;
    }
    if args.port == Some(0) {
        return Err(fail(EXIT_CONFIG, "--port must be between 1 and 65535"));
    }
    if args.connect_timeout == Some(0) {
        return Err(fail(EXIT_CONFIG, "--connect-timeout must be at least 1"));
    }
    for spec in &args.local_forwards {
        validate_simple_token("-L", spec, &[])?;
    }
    match args.strict_host_key_checking.as_str() {
        "accept-new" | "yes" => {}
        other => {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "refusing --strict-host-key-checking {other:?}: only \"accept-new\" or \"yes\" is allowed"
                ),
            ));
        }
    }
    if let Some(path) = &args.known_hosts_file {
        validate_known_hosts_path(path)?;
    }
    Ok(())
}

fn validate_simple_token(flag: &str, value: &str, extra_forbidden: &[char]) -> CliResult<()> {
    if value.is_empty() {
        return Err(fail(EXIT_CONFIG, format!("{flag} must not be empty")));
    }
    if value.starts_with('-') {
        return Err(fail(
            EXIT_CONFIG,
            format!("{flag} value {value:?} must not begin with '-'"),
        ));
    }
    if value.chars().any(|c| {
        c.is_ascii_control() || c.is_whitespace() || c == '\u{7f}' || extra_forbidden.contains(&c)
    }) {
        return Err(fail(
            EXIT_CONFIG,
            format!("{flag} value {value:?} contains invalid characters"),
        ));
    }
    Ok(())
}

fn validate_known_hosts_path(path: &Path) -> CliResult<()> {
    let raw = path
        .to_str()
        .ok_or_else(|| fail(EXIT_CONFIG, "--known-hosts-file must be valid UTF-8"))?;
    if raw.is_empty() {
        return Err(fail(EXIT_CONFIG, "--known-hosts-file must not be empty"));
    }
    if raw
        .chars()
        .any(|c| c.is_ascii_control() || c.is_whitespace() || c == '\u{7f}' || c == '"')
    {
        return Err(fail(
            EXIT_CONFIG,
            format!(
                "--known-hosts-file {raw:?} contains whitespace, quotes, or control characters"
            ),
        ));
    }
    if raw.eq_ignore_ascii_case("none") {
        return Err(fail(
            EXIT_CONFIG,
            "refusing --known-hosts-file none: disabling host key persistence is not allowed",
        ));
    }
    if path == Path::new("/dev/null") {
        return Err(fail(
            EXIT_CONFIG,
            "refusing --known-hosts-file /dev/null: disabling host key persistence is not allowed",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let (Ok(meta), Ok(null_meta)) = (std::fs::metadata(path), std::fs::metadata("/dev/null"))
        {
            if meta.file_type().is_char_device() && meta.rdev() == null_meta.rdev() {
                return Err(fail(
                    EXIT_CONFIG,
                    format!(
                        "refusing --known-hosts-file {}: resolves to /dev/null",
                        path.display()
                    ),
                ));
            }
        }
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if !meta.is_file() {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "refusing --known-hosts-file {}: existing path is not a regular file",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn resolve_openssh_bins() -> CliResult<OpenSshBins> {
    let path_var = std::env::var_os("PATH");
    resolve_openssh_bins_in(path_var.as_deref()).map_err(|e| fail(EXIT_CONFIG, e))
}

fn resolve_openssh_bins_in(path_var: Option<&std::ffi::OsStr>) -> Result<OpenSshBins, String> {
    let paths: Vec<PathBuf> = path_var
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    let cwd = std::env::current_dir().ok();
    let find = |name: &str| -> Result<PathBuf, String> {
        for dir in &paths {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                if candidate.is_relative() {
                    if let Some(base) = &cwd {
                        return Ok(base.join(candidate));
                    }
                }
                return Ok(candidate);
            }
        }
        Err(format!(
            "required OpenSSH binary {name:?} was not found on PATH (openssh-client must be installed)"
        ))
    };
    Ok(OpenSshBins {
        ssh: find("ssh")?,
        ssh_agent: find("ssh-agent")?,
        ssh_add: find("ssh-add")?,
    })
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn format_ssh_summary(parsed: &ParsedDestination, args: &SshArgs) -> String {
    let mut parts = vec!["ssh".to_string()];
    if let Some(port) = args.port {
        parts.push("-p".to_string());
        parts.push(port.to_string());
    }
    for spec in &args.local_forwards {
        parts.push("-L".to_string());
        parts.push(spec.clone());
    }
    if args.no_remote_command {
        parts.push("-N".to_string());
    }
    parts.push(parsed.display_target(args.login_name.as_deref()));
    if !args.command.is_empty() {
        parts.push("--".to_string());
        parts.extend(args.command.iter().cloned());
    }
    parts.join(" ")
}

fn build_ssh_context(parsed: &ParsedDestination, args: &SshArgs) -> CliResult<serde_json::Value> {
    let mut structured = build_structured_context().unwrap_or(serde_json::json!({}));
    let summary = format_ssh_summary(parsed, args);

    let mut ssh_map = serde_json::Map::new();
    ssh_map.insert("target".to_string(), serde_json::Value::String(summary));
    ssh_map.insert(
        "host".to_string(),
        serde_json::Value::String(parsed.host.clone()),
    );
    if let Some(user) = parsed.effective_user(args.login_name.as_deref()) {
        ssh_map.insert(
            "user".to_string(),
            serde_json::Value::String(user.to_string()),
        );
    }
    ssh_map.insert(
        "port".to_string(),
        serde_json::json!(args.port.unwrap_or(22)),
    );
    if !args.command.is_empty() {
        ssh_map.insert("command".to_string(), serde_json::json!(args.command));
    }
    if !args.local_forwards.is_empty() {
        ssh_map.insert(
            "local_forwards".to_string(),
            serde_json::json!(args.local_forwards),
        );
    }

    if let Some(map) = structured.as_object_mut() {
        map.insert("ssh".to_string(), serde_json::Value::Object(ssh_map));
        shed_structured_to_fit(map);
        let len = serde_json::to_vec(map).map(|v| v.len()).unwrap_or(0);
        if len > MAX_STRUCTURED_BYTES {
            return Err(fail(
                EXIT_CONFIG,
                format!(
                    "the approval context is {len} bytes, over the server's {MAX_STRUCTURED_BYTES}-byte \
                     limit, and nothing left in it can be dropped — shorten the remote command or forwards, \
                     or move details into --reason"
                ),
            ));
        }
    }
    Ok(structured)
}

fn call_bound_idempotency_key(
    user_key: &str,
    parsed: &ParsedDestination,
    args: &SshArgs,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let update_str = |h: &mut Sha256, s: &str| {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    };
    let update_opt_str = |h: &mut Sha256, opt: Option<&str>| match opt {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            update_str(h, s);
        }
    };

    update_str(&mut hasher, "ssh");
    update_opt_str(
        &mut hasher,
        parsed.effective_user(args.login_name.as_deref()),
    );
    update_str(&mut hasher, &parsed.host);
    hasher.update(args.port.unwrap_or(22).to_be_bytes());
    hasher.update((args.command.len() as u64).to_be_bytes());
    for tok in &args.command {
        update_str(&mut hasher, tok);
    }
    hasher.update([args.force_tty.min(2)]);
    hasher.update([u8::from(args.disable_tty)]);
    hasher.update([u8::from(args.no_remote_command)]);
    hasher.update((args.local_forwards.len() as u64).to_be_bytes());
    for spec in &args.local_forwards {
        update_str(&mut hasher, spec);
    }
    let addr_family = match (args.ipv4, args.ipv6) {
        (true, false) => 4u8,
        (false, true) => 6u8,
        _ => 0u8,
    };
    hasher.update([addr_family]);
    match args.connect_timeout {
        None => hasher.update([0u8]),
        Some(secs) => {
            hasher.update([1u8]);
            hasher.update(secs.to_be_bytes());
        }
    }
    update_str(&mut hasher, &args.strict_host_key_checking);
    update_opt_str(
        &mut hasher,
        args.known_hosts_file.as_ref().and_then(|p| p.to_str()),
    );

    let digest = hex::encode(hasher.finalize());
    format!("{user_key}-{}", &digest[..CALL_BINDING_HEX_CHARS])
}

/// Decode the granted secret and normalize CRLF / missing trailing newline so
/// keys stored via browser textarea or `keychute store` without `--raw` still
/// parse cleanly in OpenSSH `ssh-add -`.
fn decode_and_normalize_key(
    released: &mut keychute_types::ReadGrantResponse,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let mut raw = match released.encoding {
        SecretEncoding::Utf8 => Zeroizing::new(released.secret.as_bytes().to_vec()),
        SecretEncoding::Base64 => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&released.secret)
                .map_err(|_| fail(EXIT_OTHER, "server sent invalid base64 payload"))?;
            Zeroizing::new(decoded)
        }
    };
    released.secret.zeroize();

    if raw.is_empty() || raw.contains(&0) {
        raw.zeroize();
        return Err(fail(
            EXIT_OTHER,
            "the released secret is empty or binary and cannot be loaded as an SSH private key",
        ));
    }

    let normalized = normalize_pem_bytes(&raw);
    raw.zeroize();
    Ok(normalized)
}

fn normalize_pem_bytes(raw: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(raw.len() + 1));
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    if out.last() != Some(&b'\n') {
        out.push(b'\n');
    }
    out
}

fn create_socket_dir() -> CliResult<PathBuf> {
    let mut random_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random_bytes);
    let dirname = format!("kc-ssh-{}", hex::encode(random_bytes));

    let temp_base = std::env::temp_dir();
    let base = if temp_base.join(&dirname).join("s").as_os_str().len() < MAX_SOCKET_PATH_BYTES {
        temp_base
    } else {
        PathBuf::from("/tmp")
    };
    let dir = base.join(&dirname);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| {
                fail(
                    EXIT_OTHER,
                    format!(
                        "failed creating ssh-agent socket dir {}: {e}",
                        dir.display()
                    ),
                )
            })?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            fail(
                EXIT_OTHER,
                format!("failed setting 0700 permissions on {}: {e}", dir.display()),
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(&dir).map_err(|e| {
            fail(
                EXIT_OTHER,
                format!(
                    "failed creating ssh-agent socket dir {}: {e}",
                    dir.display()
                ),
            )
        })?;
    }
    Ok(dir)
}

async fn start_ephemeral_agent(
    bins: &OpenSshBins,
    key_lifetime_secs: u64,
) -> CliResult<AgentGuard> {
    let dir = create_socket_dir()?;
    let sock = dir.join("s");
    let mut guard = AgentGuard::new(dir.clone());

    let mut cmd = tokio::process::Command::new(&bins.ssh_agent);
    cmd.current_dir(&dir)
        .arg("-D")
        .arg("-t")
        .arg(key_lifetime_secs.to_string())
        .arg("-a")
        .arg("s")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        // Isolate ssh-agent from terminal SIGINT so interactive Ctrl-C does not
        // tear down the agent while an SSH session is still active.
        cmd.process_group(0);
    }

    let child = cmd.spawn().map_err(|e| {
        fail(
            EXIT_OTHER,
            format!("failed starting {}: {e}", bins.ssh_agent.display()),
        )
    })?;
    guard.child = Some(child);

    for _ in 0..AGENT_READY_POLL_ATTEMPTS {
        if let Some(child) = guard.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let msg = format!("ssh-agent exited before becoming ready ({status})");
                    guard.shutdown().await;
                    return Err(fail(EXIT_OTHER, msg));
                }
                Ok(None) => {}
                Err(e) => {
                    guard.shutdown().await;
                    return Err(fail(EXIT_OTHER, format!("failed checking ssh-agent: {e}")));
                }
            }
        }
        #[cfg(unix)]
        if tokio::net::UnixStream::connect(&sock).await.is_ok() {
            return Ok(guard);
        }
        tokio::time::sleep(AGENT_READY_POLL_INTERVAL).await;
    }

    guard.shutdown().await;
    Err(fail(EXIT_OTHER, "timed out waiting for ssh-agent socket"))
}

async fn load_key_into_agent(
    bins: &OpenSshBins,
    sock: &Path,
    key_bytes: &mut Zeroizing<Vec<u8>>,
    key_lifetime_secs: u64,
) -> CliResult<()> {
    let mut cmd = tokio::process::Command::new(&bins.ssh_add);
    cmd.arg("-q")
        .arg("-t")
        .arg(key_lifetime_secs.to_string())
        .arg("-")
        .env("SSH_AUTH_SOCK", sock)
        .env("SSH_ASKPASS", "/bin/false")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .env_remove("DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| {
        fail(
            EXIT_OTHER,
            format!("failed starting {}: {e}", bins.ssh_add.display()),
        )
    })?;

    let write_res = async {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("ssh-add stdin was not piped"))?;
        stdin.write_all(key_bytes).await?;
        stdin.shutdown().await?;
        drop(stdin);
        Ok::<(), std::io::Error>(())
    }
    .await;
    key_bytes.zeroize();

    if let Err(e) = write_res {
        let _ = child.kill().await;
        return Err(fail(
            EXIT_OTHER,
            format!("failed sending SSH private key to ssh-add: {e}"),
        ));
    }

    let out = child
        .wait_with_output()
        .await
        .map_err(|e| fail(EXIT_OTHER, format!("failed waiting for ssh-add: {e}")))?;

    if !out.status.success() {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if detail.is_empty() {
            format!(
                "ssh-add rejected the released secret ({}); check that the secret is a valid unencrypted SSH private key",
                out.status
            )
        } else {
            format!("ssh-add rejected the released secret: {detail}")
        };
        return Err(fail(EXIT_OTHER, msg));
    }
    Ok(())
}

fn build_ssh_argv(parsed: &ParsedDestination, args: &SshArgs) -> Vec<String> {
    let mut argv = vec![
        "-F".to_string(),
        "none".to_string(),
        "-o".to_string(),
        "IdentityAgent=SSH_AUTH_SOCK".to_string(),
        "-o".to_string(),
        "IdentityFile=none".to_string(),
        "-o".to_string(),
        "IdentitiesOnly=no".to_string(),
        "-o".to_string(),
        "ForwardAgent=no".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("StrictHostKeyChecking={}", args.strict_host_key_checking),
    ];

    if let Some(kh) = &args.known_hosts_file {
        argv.push("-o".to_string());
        argv.push(format!("UserKnownHostsFile={}", kh.display()));
    }
    if let Some(ct) = args.connect_timeout {
        argv.push("-o".to_string());
        argv.push(format!("ConnectTimeout={ct}"));
    }
    if args.ipv4 {
        argv.push("-4".to_string());
    } else if args.ipv6 {
        argv.push("-6".to_string());
    }
    if let Some(port) = args.port {
        argv.push("-p".to_string());
        argv.push(port.to_string());
    }
    if let Some(user) = &args.login_name {
        argv.push("-l".to_string());
        argv.push(user.clone());
    }
    match args.force_tty {
        0 => {}
        1 => argv.push("-t".to_string()),
        _ => argv.push("-tt".to_string()),
    }
    if args.disable_tty {
        argv.push("-T".to_string());
    }
    if args.no_remote_command {
        argv.push("-N".to_string());
    }
    if args.quiet {
        argv.push("-q".to_string());
    } else if args.verbose > 0 {
        argv.push(format!("-{}", "v".repeat(args.verbose.min(3) as usize)));
    }
    for spec in &args.local_forwards {
        argv.push("-L".to_string());
        argv.push(spec.clone());
    }
    argv.push("--".to_string());
    argv.push(parsed.ssh_target_arg());
    argv.extend(args.command.iter().cloned());
    argv
}

async fn run_ssh_child(
    bins: &OpenSshBins,
    sock: &Path,
    parsed: &ParsedDestination,
    args: &SshArgs,
    guard: &mut AgentGuard,
    #[cfg(unix)] signals: &mut UnixSignals,
) -> CliResult<ExitStatus> {
    let mut cmd = tokio::process::Command::new(&bins.ssh);
    cmd.env("SSH_AUTH_SOCK", sock)
        .args(build_ssh_argv(parsed, args));

    #[cfg(unix)]
    {
        let _ = std::io::stderr().flush();
        let mut child = cmd.spawn().map_err(|e| {
            fail(
                EXIT_OTHER,
                format!("failed starting {}: {e}", bins.ssh.display()),
            )
        })?;

        loop {
            tokio::select! {
                res = child.wait() => {
                    return res.map_err(|e| fail(EXIT_OTHER, format!("failed waiting for ssh: {e}")));
                }
                _ = signals.sigint.recv() => {
                    // Let the foreground ssh child handle interactive Ctrl-C.
                }
                _ = signals.sigterm.recv() => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    guard.shutdown().await;
                    return Err(crate::silent_exit(143));
                }
                _ = signals.sighup.recv() => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    guard.shutdown().await;
                    return Err(crate::silent_exit(129));
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = guard;
        let _ = std::io::stderr().flush();
        let mut child = cmd.spawn().map_err(|e| {
            fail(
                EXIT_OTHER,
                format!("failed starting {}: {e}", bins.ssh.display()),
            )
        })?;
        child
            .wait()
            .await
            .map_err(|e| fail(EXIT_OTHER, format!("failed waiting for ssh: {e}")))
    }
}

fn exit_code_from_status(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    EXIT_OTHER
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::Parser;

    fn parse_ssh(args: &[&str]) -> SshArgs {
        let mut full = vec!["keychute", "ssh"];
        full.extend_from_slice(args);
        match Cli::parse_from(full).cmd {
            Cmd::Ssh(a) => a,
            _ => panic!("expected ssh subcommand"),
        }
    }

    #[test]
    fn destination_parsing_accepts_valid_forms_and_rejects_ambiguous_ones() {
        assert_eq!(
            parse_destination("grotten").unwrap(),
            ParsedDestination {
                inline_user: None,
                host: "grotten".into(),
            }
        );
        assert_eq!(
            parse_destination("ansibleadm@aachen.cloud.andrewgarrett.dev").unwrap(),
            ParsedDestination {
                inline_user: Some("ansibleadm".into()),
                host: "aachen.cloud.andrewgarrett.dev".into(),
            }
        );
        assert_eq!(
            parse_destination("ubnt@[::1]").unwrap(),
            ParsedDestination {
                inline_user: Some("ubnt".into()),
                host: "::1".into(),
            }
        );
        assert_eq!(
            parse_destination("::1").unwrap(),
            ParsedDestination {
                inline_user: None,
                host: "::1".into(),
            }
        );

        for bad in [
            "",
            "-oProxyCommand=id",
            "-grotten",
            "ssh://ubnt@192.168.124.1",
            "host:2222",
            "[::1]:2222",
            "user@host:2222",
            "@host",
            "user@",
            "a@b@c",
            "user@-host",
            "-user@host",
            "host name",
            "host\n",
            "host/path",
            "host?x=1",
            "host#frag",
            "[not-ipv6]",
            "[::1",
        ] {
            assert!(
                parse_destination(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn option_validation_enforces_security_and_server_bounds() {
        let base = parse_ssh(&["ansibleadm@grotten", "--secret", "node-ssh-key"]);
        let parsed = parse_destination(&base.destination).unwrap();
        assert!(validate_options(&base, &parsed).is_ok());

        // Refuses StrictHostKeyChecking=no / off.
        for bad_mode in ["no", "off", "ask", ""] {
            let a = parse_ssh(&[
                "grotten",
                "--secret",
                "k",
                "--strict-host-key-checking",
                bad_mode,
            ]);
            let p = parse_destination(&a.destination).unwrap();
            assert_eq!(validate_options(&a, &p).unwrap_err().code, EXIT_CONFIG);
        }
        let yes = parse_ssh(&[
            "grotten",
            "--secret",
            "k",
            "--strict-host-key-checking",
            "yes",
        ]);
        assert!(validate_options(&yes, &parse_destination(&yes.destination).unwrap()).is_ok());

        // Refuses /dev/null and OpenSSH's `none` sentinel for known_hosts_file.
        for bad_kh in ["/dev/null", "none", "NONE", "/tmp"] {
            let parsed_cmd = parse_ssh(&["grotten", "--secret", "k", "--known-hosts-file", bad_kh]);
            assert_eq!(
                validate_options(
                    &parsed_cmd,
                    &parse_destination(&parsed_cmd.destination).unwrap()
                )
                .unwrap_err()
                .code,
                EXIT_CONFIG,
                "expected {bad_kh:?} to be rejected"
            );
        }
        // Refuses whitespace/quotes in known_hosts_file.
        let bad_kh = parse_ssh(&[
            "grotten",
            "--secret",
            "k",
            "--known-hosts-file",
            "/tmp/my known_hosts",
        ]);
        assert_eq!(
            validate_options(&bad_kh, &parse_destination(&bad_kh.destination).unwrap())
                .unwrap_err()
                .code,
            EXIT_CONFIG
        );

        // Refuses combining -l with user@host.
        let both_users = parse_ssh(&["ansibleadm@grotten", "-l", "root", "--secret", "k"]);
        assert_eq!(
            validate_options(
                &both_users,
                &parse_destination(&both_users.destination).unwrap()
            )
            .unwrap_err()
            .code,
            EXIT_CONFIG
        );

        // Refuses port 0 and connect_timeout 0.
        let port0 = parse_ssh(&["grotten", "-p", "0", "--secret", "k"]);
        assert_eq!(
            validate_options(&port0, &parse_destination(&port0.destination).unwrap())
                .unwrap_err()
                .code,
            EXIT_CONFIG
        );
        let ct0 = parse_ssh(&["grotten", "--connect-timeout", "0", "--secret", "k"]);
        assert_eq!(
            validate_options(&ct0, &parse_destination(&ct0.destination).unwrap())
                .unwrap_err()
                .code,
            EXIT_CONFIG
        );

        // Refuses empty/oversize idempotency key.
        let empty_key = parse_ssh(&["grotten", "--secret", "k", "--idempotency-key", ""]);
        assert_eq!(
            validate_options(
                &empty_key,
                &parse_destination(&empty_key.destination).unwrap()
            )
            .unwrap_err()
            .code,
            EXIT_CONFIG
        );
        let long_key = parse_ssh(&[
            "grotten",
            "--secret",
            "k",
            "--idempotency-key",
            &"x".repeat(MAX_SSH_USER_KEY_BYTES + 1),
        ]);
        assert_eq!(
            validate_options(
                &long_key,
                &parse_destination(&long_key.destination).unwrap()
            )
            .unwrap_err()
            .code,
            EXIT_CONFIG
        );
    }

    #[test]
    fn clap_conflicts_and_unknown_flags_reject() {
        assert!(
            Cli::try_parse_from(["keychute", "ssh", "host", "--secret", "k", "-t", "-T"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["keychute", "ssh", "host", "--secret", "k", "-4", "-6"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["keychute", "ssh", "host", "--secret", "k", "-q", "-v"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["keychute", "ssh", "host", "--secret", "k", "-N", "uname"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["keychute", "ssh", "host", "--secret", "k", "-A"]).is_err());
    }

    #[test]
    fn ssh_argv_forces_isolated_agent_and_safe_defaults() {
        let args = parse_ssh(&[
            "ansibleadm@grotten",
            "--secret",
            "node-ssh-key",
            "-p",
            "2222",
            "-4",
            "-tt",
            "-vv",
            "-L",
            "8080:127.0.0.1:80",
            "--connect-timeout",
            "10",
            "--known-hosts-file",
            "/tmp/kh",
            "--",
            "sudo",
            "systemctl",
            "status",
            "k3s",
        ]);
        let parsed = parse_destination(&args.destination).unwrap();
        let argv = build_ssh_argv(&parsed, &args);
        assert_eq!(
            argv,
            vec![
                "-F",
                "none",
                "-o",
                "IdentityAgent=SSH_AUTH_SOCK",
                "-o",
                "IdentityFile=none",
                "-o",
                "IdentitiesOnly=no",
                "-o",
                "ForwardAgent=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "UserKnownHostsFile=/tmp/kh",
                "-o",
                "ConnectTimeout=10",
                "-4",
                "-p",
                "2222",
                "-tt",
                "-vv",
                "-L",
                "8080:127.0.0.1:80",
                "--",
                "ansibleadm@grotten",
                "sudo",
                "systemctl",
                "status",
                "k3s",
            ]
        );
    }

    #[test]
    fn pem_normalization_handles_crlf_and_missing_trailing_newline() {
        assert_eq!(
            &*normalize_pem_bytes(b"LINE1\r\nLINE2\r\n"),
            b"LINE1\nLINE2\n"
        );
        assert_eq!(&*normalize_pem_bytes(b"LINE1\r\nLINE2"), b"LINE1\nLINE2\n");
        assert_eq!(&*normalize_pem_bytes(b"LINE1\nLINE2\n"), b"LINE1\nLINE2\n");
    }

    #[test]
    fn idempotency_key_binds_session_parameters() {
        let a1 = parse_ssh(&["ansibleadm@grotten", "--secret", "k", "--", "uptime"]);
        let a2 = parse_ssh(&["ansibleadm@grotten", "--secret", "k", "--", "id"]);
        let a3 = parse_ssh(&["ansibleadm@take5", "--secret", "k", "--", "uptime"]);
        let a4 = parse_ssh(&[
            "ansibleadm@grotten",
            "--secret",
            "k",
            "-p",
            "2222",
            "--",
            "uptime",
        ]);
        let p1 = parse_destination(&a1.destination).unwrap();
        let p2 = parse_destination(&a2.destination).unwrap();
        let p3 = parse_destination(&a3.destination).unwrap();
        let p4 = parse_destination(&a4.destination).unwrap();

        let k1 = call_bound_idempotency_key("same", &p1, &a1);
        let k1_again = call_bound_idempotency_key("same", &p1, &a1);
        let k2 = call_bound_idempotency_key("same", &p2, &a2);
        let k3 = call_bound_idempotency_key("same", &p3, &a3);
        let k4 = call_bound_idempotency_key("same", &p4, &a4);
        assert_eq!(k1, k1_again);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
        assert!(k1.len() <= 124);
    }

    #[test]
    fn binary_or_empty_secret_is_rejected_without_echoing_bytes() {
        let mut empty = keychute_types::ReadGrantResponse {
            secret: String::new(),
            encoding: SecretEncoding::Utf8,
            secret_version_id: uuid::Uuid::new_v4(),
        };
        assert_eq!(
            decode_and_normalize_key(&mut empty).unwrap_err().code,
            EXIT_OTHER
        );

        let mut nul = keychute_types::ReadGrantResponse {
            secret: "c2VjcmV0LWJ5dGVzAA==".to_string(),
            encoding: SecretEncoding::Base64,
            secret_version_id: uuid::Uuid::new_v4(),
        };
        let err = decode_and_normalize_key(&mut nul).unwrap_err();
        assert_eq!(err.code, EXIT_OTHER);
        assert!(!err.message.contains("secret-bytes"));
    }

    #[test]
    fn missing_openssh_binary_returns_clear_error() {
        let err = resolve_openssh_bins_in(Some(std::ffi::OsStr::new("/nonexistent-keychute-bin")));
        let msg = match err {
            Ok(_) => panic!("expected missing binary error"),
            Err(m) => m,
        };
        assert!(msg.contains("not found on PATH"), "{msg}");
    }

    #[test]
    fn agent_key_lifetime_bounds_track_connect_timeout() {
        assert_eq!(agent_key_lifetime_seconds(None), 60);
        assert_eq!(agent_key_lifetime_seconds(Some(5)), 60);
        assert_eq!(agent_key_lifetime_seconds(Some(90)), 120);
        assert_eq!(agent_key_lifetime_seconds(Some(600)), 300);
    }
}
