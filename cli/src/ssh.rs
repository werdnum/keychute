//! `keychute ssh` — run OpenSSH `ssh` using a private key stored in Keychute
//! (CUJ 2c, tier-2 `cli-read`) without ever writing key bytes to stdout or disk.
//!
//! This subcommand is a thin tier-2 wrapper around OpenSSH `ssh`, not an `ssh`
//! re-implementation. It requests a single-use `cli-read` grant (attaching the
//! claimed invocation as context), loads the released key into an isolated
//! ephemeral `ssh-agent` whose Unix socket lives in a `0700` temp directory,
//! runs `ssh` with safe default agent/batch options while passing `SSH_ARGS`
//! through, and tears down `ssh-agent` before propagating `ssh`'s exit code.

use std::io::Write;
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
const MAX_SUMMARY_CHARS: usize = 1024;
/// 32 hex chars of SHA-256 + `-` separator, leaving 91 bytes for caller keys
/// under the shared 124-byte `validate_idempotency_key` cap.
const CALL_BINDING_HEX_CHARS: usize = 32;
pub(crate) const MAX_SSH_USER_KEY_BYTES: usize = 124 - (CALL_BINDING_HEX_CHARS + 1);
/// Conservative Unix domain socket path bound (macOS/Linux `sun_path` is 104/108
/// bytes; leave margin for NUL and directory suffix).
const MAX_SOCKET_PATH_BYTES: usize = 100;
const AGENT_READY_POLL_ATTEMPTS: usize = 500;
const AGENT_READY_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Orphan-leak backstop (`ssh-agent -t` / `ssh-add -t`) so uncatchable
/// `SIGKILL` cannot leave a private key resident in memory indefinitely.
const AGENT_ORPHAN_BACKSTOP_SECONDS: u64 = 3600;

/// Single-letter OpenSSH `ssh` options that take a separate argument.
const SSH_ARG_OPTIONS: &[u8] = b"BbcDEeFIiJLlmOopPQRSWw";

#[derive(clap::Args)]
pub(crate) struct SshArgs {
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
    /// Arguments passed directly to OpenSSH `ssh` (`[ssh-options] destination [command ...]`).
    /// Pass `--` before any `ssh` flags or remote command flags starting with `-`.
    #[arg(required = true, num_args = 1.., value_name = "SSH_ARGS")]
    pub ssh_args: Vec<String>,
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
    validate_keychute_args(&args)?;
    let bins = resolve_openssh_bins()?;
    let structured = build_ssh_context(&args)?;

    let user_key = args
        .idempotency_key
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let idem_key = call_bound_idempotency_key(&user_key, &args.secret, &args.ssh_args);

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
    let key_lifetime_secs = AGENT_ORPHAN_BACKSTOP_SECONDS;

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

    let ssh_argv = build_ssh_argv(&args.ssh_args);
    #[cfg(unix)]
    let ssh_res = run_ssh_child(&bins, &sock, &ssh_argv, &mut guard, &mut signals).await;
    #[cfg(not(unix))]
    let ssh_res = run_ssh_child(&bins, &sock, &ssh_argv, &mut guard).await;
    guard.shutdown().await;
    let status = ssh_res?;
    if status.success() {
        return Ok(());
    }
    Err(crate::silent_exit(exit_code_from_status(status)))
}

fn validate_keychute_args(args: &SshArgs) -> CliResult<()> {
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

fn format_ssh_summary(ssh_args: &[String]) -> String {
    let mut out = String::from("ssh");
    for arg in ssh_args {
        out.push(' ');
        if arg.is_empty()
            || arg
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\'' | '"'))
        {
            out.push('\'');
            for ch in arg.chars() {
                if ch == '\'' {
                    out.push_str("'\"'\"'");
                } else {
                    out.push(ch);
                }
            }
            out.push('\'');
        } else {
            out.push_str(arg);
        }
    }
    if out.chars().count() > MAX_SUMMARY_CHARS {
        let mut truncated: String = out.chars().take(MAX_SUMMARY_CHARS - 1).collect();
        truncated.push('…');
        return truncated;
    }
    out
}

fn build_ssh_context(args: &SshArgs) -> CliResult<serde_json::Value> {
    let mut structured = build_structured_context().unwrap_or(serde_json::json!({}));
    let summary = format_ssh_summary(&args.ssh_args);

    let mut ssh_map = serde_json::Map::new();
    ssh_map.insert("target".to_string(), serde_json::Value::String(summary));
    ssh_map.insert("argv".to_string(), serde_json::json!(args.ssh_args));

    if let Some(map) = structured.as_object_mut() {
        map.insert("ssh".to_string(), serde_json::Value::Object(ssh_map));
        shed_structured_to_fit(map);
        let len = serde_json::to_vec(map).map(|v| v.len()).unwrap_or(0);
        if len > MAX_STRUCTURED_BYTES {
            if let Some(ssh_obj) = map.get_mut("ssh").and_then(|v| v.as_object_mut()) {
                ssh_obj.remove("argv");
            }
            let trimmed_len = serde_json::to_vec(map).map(|v| v.len()).unwrap_or(0);
            if trimmed_len > MAX_STRUCTURED_BYTES {
                return Err(fail(
                    EXIT_CONFIG,
                    format!(
                        "the approval context is {trimmed_len} bytes, over the server's {MAX_STRUCTURED_BYTES}-byte \
                         limit — shorten the SSH arguments or move details into --reason"
                    ),
                ));
            }
        }
    }
    Ok(structured)
}

fn call_bound_idempotency_key(user_key: &str, secret: &str, ssh_args: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let update_str = |h: &mut Sha256, s: &str| {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    };

    update_str(&mut hasher, "ssh");
    update_str(&mut hasher, secret);
    hasher.update((ssh_args.len() as u64).to_be_bytes());
    for tok in ssh_args {
        update_str(&mut hasher, tok);
    }

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
        if i + 1 < raw.len() && raw[i] == b'\r' && raw[i + 1] == b'\n' {
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
        // tear down the agent before keychute finishes reaping ssh.
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
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env_remove("DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        // Detach from the foreground terminal process group alongside
        // SSH_ASKPASS_REQUIRE=force so encrypted keys fail immediately without
        // blocking on /dev/tty.
        cmd.process_group(0);
    }

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

#[derive(Default)]
struct CallerSshOverrides {
    config_file: bool,
    identity_file: bool,
    identities_only: bool,
    forward_agent: bool,
    batch_mode: bool,
    strict_host_key_checking: bool,
}

impl CallerSshOverrides {
    fn record_o_value(&mut self, spec: &str) {
        let key = spec
            .split(['=', ' ', '\t'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match key.as_str() {
            "identityfile" => self.identity_file = true,
            "identitiesonly" => self.identities_only = true,
            "forwardagent" => self.forward_agent = true,
            "batchmode" => self.batch_mode = true,
            "stricthostkeychecking" => self.strict_host_key_checking = true,
            _ => {}
        }
    }
}

/// Scan leading OpenSSH option arguments before the destination token so our
/// safer defaults never silently clobber an option the caller explicitly passed.
fn scan_caller_overrides(ssh_args: &[String]) -> CallerSshOverrides {
    let mut out = CallerSshOverrides::default();
    let mut i = 0;
    while i < ssh_args.len() {
        let arg = &ssh_args[i];
        if arg == "--" || !arg.starts_with('-') || arg == "-" {
            break;
        }
        let bytes = arg.as_bytes();
        let mut j = 1;
        while j < bytes.len() {
            let opt = bytes[j];
            if SSH_ARG_OPTIONS.contains(&opt) {
                let inline_val = (j + 1 < bytes.len()).then(|| &arg[j + 1..]);
                let val = inline_val.or_else(|| {
                    i += 1;
                    ssh_args.get(i).map(String::as_str)
                });
                match opt {
                    b'F' => out.config_file = true,
                    b'i' => out.identity_file = true,
                    b'o' => {
                        if let Some(v) = val {
                            out.record_o_value(v);
                        }
                    }
                    _ => {}
                }
                break;
            }
            if opt == b'A' {
                out.forward_agent = true;
            }
            j += 1;
        }
        i += 1;
    }
    out
}

fn build_ssh_argv(ssh_args: &[String]) -> Vec<String> {
    let seen = scan_caller_overrides(ssh_args);
    let mut argv = Vec::with_capacity(ssh_args.len() + 14);
    let push_opt = |v: &mut Vec<String>, opt: &str| {
        v.push("-o".to_string());
        v.push(opt.to_string());
    };

    if !seen.config_file {
        argv.push("-F".to_string());
        argv.push("none".to_string());
    }
    push_opt(&mut argv, "IdentityAgent=SSH_AUTH_SOCK");
    if !seen.identity_file {
        push_opt(&mut argv, "IdentityFile=none");
        if !seen.identities_only {
            push_opt(&mut argv, "IdentitiesOnly=no");
        }
    }
    if !seen.forward_agent {
        push_opt(&mut argv, "ForwardAgent=no");
    }
    if !seen.batch_mode {
        push_opt(&mut argv, "BatchMode=yes");
    }
    if !seen.strict_host_key_checking {
        push_opt(&mut argv, "StrictHostKeyChecking=accept-new");
    }
    argv.extend(ssh_args.iter().cloned());
    argv
}

#[cfg(unix)]
fn forward_sigint_to_child(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let pid_str = pid.to_string();
    let sent = std::process::Command::new("/bin/kill")
        .args(["-INT", &pid_str])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .or_else(|_| {
            std::process::Command::new("kill")
                .args(["-INT", &pid_str])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        })
        .map(|s| s.success())
        .unwrap_or(false);
    if !sent {
        let _ = child.start_kill();
    }
}

async fn run_ssh_child(
    bins: &OpenSshBins,
    sock: &Path,
    argv: &[String],
    guard: &mut AgentGuard,
    #[cfg(unix)] signals: &mut UnixSignals,
) -> CliResult<ExitStatus> {
    let mut cmd = tokio::process::Command::new(&bins.ssh);
    cmd.env("SSH_AUTH_SOCK", sock).args(argv);

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
                    forward_sigint_to_child(&mut child);
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
    fn cli_accepts_destination_first_and_flags_after_separator() {
        let a1 = parse_ssh(&[
            "ansibleadm@grotten",
            "--secret",
            "node-ssh-key",
            "--reason",
            "check k3s",
            "--",
            "sudo",
            "systemctl",
            "status",
            "k3s",
        ]);
        assert_eq!(a1.secret, "node-ssh-key");
        assert_eq!(a1.reason, "check k3s");
        assert_eq!(
            a1.ssh_args,
            vec!["ansibleadm@grotten", "sudo", "systemctl", "status", "k3s"]
        );

        let a2 = parse_ssh(&[
            "--secret",
            "node-ssh-key",
            "--",
            "-p",
            "2222",
            "-L",
            "8080:127.0.0.1:80",
            "-N",
            "ansibleadm@grotten",
        ]);
        assert_eq!(
            a2.ssh_args,
            vec![
                "-p",
                "2222",
                "-L",
                "8080:127.0.0.1:80",
                "-N",
                "ansibleadm@grotten"
            ]
        );
    }

    #[test]
    fn keychute_arg_validation_enforces_bounds() {
        let valid = parse_ssh(&["grotten", "--secret", "node-ssh-key"]);
        assert!(validate_keychute_args(&valid).is_ok());

        let empty_secret = parse_ssh(&["grotten", "--secret", ""]);
        assert_eq!(
            validate_keychute_args(&empty_secret).unwrap_err().code,
            EXIT_CONFIG
        );

        let zero_ttl = parse_ssh(&["grotten", "--secret", "k", "--ttl", "0"]);
        assert_eq!(
            validate_keychute_args(&zero_ttl).unwrap_err().code,
            EXIT_CONFIG
        );

        let empty_key = parse_ssh(&["grotten", "--secret", "k", "--idempotency-key", ""]);
        assert_eq!(
            validate_keychute_args(&empty_key).unwrap_err().code,
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
            validate_keychute_args(&long_key).unwrap_err().code,
            EXIT_CONFIG
        );
    }

    #[test]
    fn ssh_argv_applies_safe_defaults_and_honours_caller_overrides() {
        let default_args = parse_ssh(&[
            "ansibleadm@grotten",
            "--secret",
            "node-ssh-key",
            "--",
            "ls",
            "-F",
        ]);
        assert_eq!(
            build_ssh_argv(&default_args.ssh_args),
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
                "ansibleadm@grotten",
                "ls",
                "-F",
            ]
        );

        let override_args = parse_ssh(&[
            "--secret",
            "k",
            "--",
            "-F",
            "/tmp/custom_cfg",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "BatchMode no",
            "-o",
            "ForwardAgent=yes",
            "-i",
            "/tmp/extra_key",
            "-p",
            "2222",
            "grotten",
        ]);
        let argv = build_ssh_argv(&override_args.ssh_args);
        assert!(!argv.windows(2).any(|w| w == ["-F", "none"]));
        assert!(argv.contains(&"IdentityAgent=SSH_AUTH_SOCK".to_string()));
        assert!(!argv.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        assert!(!argv.contains(&"BatchMode=yes".to_string()));
        assert!(!argv.contains(&"ForwardAgent=no".to_string()));
        assert!(!argv.contains(&"IdentityFile=none".to_string()));
        assert!(argv.ends_with(&[
            "-F".to_string(),
            "/tmp/custom_cfg".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            "BatchMode no".to_string(),
            "-o".to_string(),
            "ForwardAgent=yes".to_string(),
            "-i".to_string(),
            "/tmp/extra_key".to_string(),
            "-p".to_string(),
            "2222".to_string(),
            "grotten".to_string(),
        ]));

        let p_tag_args = parse_ssh(&[
            "--secret",
            "k",
            "--",
            "-P",
            "prod",
            "-o",
            "BatchMode=no",
            "grotten",
        ]);
        let p_tag_argv = build_ssh_argv(&p_tag_args.ssh_args);
        assert!(!p_tag_argv.contains(&"BatchMode=yes".to_string()));
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
    fn idempotency_key_binds_secret_and_ssh_args() {
        let a1 = &["ansibleadm@grotten", "uptime"].map(str::to_string);
        let a2 = &["ansibleadm@grotten", "id"].map(str::to_string);
        let k1 = call_bound_idempotency_key("same", "node-ssh-key", a1);
        let k1_again = call_bound_idempotency_key("same", "node-ssh-key", a1);
        let k2 = call_bound_idempotency_key("same", "node-ssh-key", a2);
        let k3 = call_bound_idempotency_key("same", "other-key", a1);
        assert_eq!(k1, k1_again);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert!(k1.len() <= 124);
    }

    #[test]
    fn summary_formats_and_truncates_cleanly() {
        assert_eq!(
            format_ssh_summary(&[
                "ansibleadm@grotten".into(),
                "sh".into(),
                "-c".into(),
                "echo hi".into(),
            ]),
            "ssh ansibleadm@grotten sh -c 'echo hi'"
        );
        let huge = vec!["ansibleadm@grotten".into(), "x".repeat(2000)];
        let truncated = format_ssh_summary(&huge);
        assert_eq!(truncated.chars().count(), MAX_SUMMARY_CHARS);
        assert!(truncated.ends_with('…'));
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
}
