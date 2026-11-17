//! End-to-end test of `keychute ssh` against a local axum mock server, real
//! `ssh-agent` / `ssh-add`, and a recording fake `ssh` script on `PATH`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

const REQUEST_ID: &str = "11111111-1111-1111-1111-111111111111";
const GRANT_ID: &str = "22222222-2222-2222-2222-222222222222";

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct MockConfig {
    secret_payload: Vec<u8>,
    deny: bool,
    granted_secret_name: Option<String>,
    auto_approved: bool,
}

#[derive(Clone)]
struct MockState {
    cfg: MockConfig,
    create_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
    wait_calls: Arc<AtomicUsize>,
    read_calls: Arc<AtomicUsize>,
}

async fn create_request(
    State(st): State<MockState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    st.create_bodies.lock().unwrap().push(body);
    if st.cfg.auto_approved {
        return (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "request_id": REQUEST_ID,
                "state": "approved",
                "grant_id": GRANT_ID,
                "granted_secret_name": st.cfg.granted_secret_name,
                "auto_approved": true,
            })),
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "pending",
        })),
    )
}

async fn wait_request(
    State(st): State<MockState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Json<serde_json::Value> {
    assert_eq!(id.to_string(), REQUEST_ID);
    let n = st.wait_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        return Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "pending",
        }));
    }
    if st.cfg.deny {
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "denied",
            "deny_reason": "not today",
        }))
    } else {
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "approved",
            "grant_id": GRANT_ID,
            "granted_secret_name": st.cfg.granted_secret_name,
        }))
    }
}

async fn read_grant(
    State(st): State<MockState>,
    AxumPath(id): AxumPath<Uuid>,
) -> (StatusCode, String) {
    assert_eq!(id.to_string(), GRANT_ID);
    st.read_calls.fetch_add(1, Ordering::SeqCst);
    let secret = String::from_utf8(st.cfg.secret_payload.clone()).unwrap();
    (
        StatusCode::OK,
        serde_json::json!({
            "secret": secret,
            "encoding": "utf8",
            "secret_version_id": "33333333-3333-3333-3333-333333333333",
        })
        .to_string(),
    )
}

async fn start_mock(cfg: MockConfig) -> (String, MockState) {
    let state = MockState {
        cfg,
        create_bodies: Arc::new(Mutex::new(Vec::new())),
        wait_calls: Arc::new(AtomicUsize::new(0)),
        read_calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/v1/access-requests", post(create_request))
        .route("/v1/access-requests/{id}/wait", get(wait_request))
        .route("/v1/grants/{id}/read", post(read_grant))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

/// Generate a throwaway Ed25519 keypair using `ssh-keygen`, return
/// `(private_key_bytes, public_key_line)`, and delete the key files.
fn generate_ed25519_keypair(dir: &Path) -> (Vec<u8>, String) {
    generate_ed25519_keypair_with_passphrase(dir, "")
}

fn generate_ed25519_keypair_with_passphrase(dir: &Path, passphrase: &str) -> (Vec<u8>, String) {
    let key_path = dir.join("test_ed25519");
    let pub_path = dir.join("test_ed25519.pub");
    let out = Command::new("ssh-keygen")
        .args([
            "-q", "-t", "ed25519", "-N", passphrase, "-C", "test-key", "-f",
        ])
        .arg(&key_path)
        .output()
        .expect("ssh-keygen must be installed");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let priv_bytes = std::fs::read(&key_path).unwrap();
    let pub_line = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_path);
    (priv_bytes, pub_line)
}

/// Create a `bin/ssh` shim that records argv, `SSH_AUTH_SOCK`, and `ssh-add -L`,
/// returning `(bin_dir, capture_dir, combined_path)`.
fn install_fake_ssh(root: &Path) -> (PathBuf, PathBuf, String) {
    let bin_dir = root.join("bin");
    let capture_dir = root.join("capture");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&capture_dir).unwrap();

    let shim = bin_dir.join("ssh");
    let script = r#"#!/bin/sh
set -eu
test -n "${SSH_AUTH_SOCK:-}"
test -S "${SSH_AUTH_SOCK}"
printf '%s\n' "${SSH_AUTH_SOCK}" > "${FAKE_SSH_CAPTURE_DIR}/sock_path"
ssh-add -L > "${FAKE_SSH_CAPTURE_DIR}/agent_keys"
: > "${FAKE_SSH_CAPTURE_DIR}/argv"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "${FAKE_SSH_CAPTURE_DIR}/argv"
done
if [ -n "${FAKE_SSH_SLEEP:-}" ]; then
  : > "${FAKE_SSH_CAPTURE_DIR}/ready"
  exec sleep "${FAKE_SSH_SLEEP}"
fi
if [ -n "${FAKE_SSH_STDOUT:-}" ]; then
  printf '%s' "${FAKE_SSH_STDOUT}"
fi
if [ -n "${FAKE_SSH_STDERR:-}" ]; then
  printf '%s\n' "${FAKE_SSH_STDERR}" >&2
fi
exit "${FAKE_SSH_EXIT:-0}"
"#;
    std::fs::write(&shim, script).unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let path_env = format!("{}:{existing_path}", bin_dir.display());
    (bin_dir, capture_dir, path_env)
}

fn run_ssh_cli(
    url: &str,
    path_env: &str,
    capture_dir: &Path,
    tmp_dir: &Path,
    extra_env: &[(&str, &str)],
    args: &[&str],
) -> std::process::Output {
    let home_dir = tmp_dir.parent().unwrap().join("home");
    std::fs::create_dir_all(&home_dir).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keychute"));
    cmd.args(args)
        .env("KEYCHUTE_URL", url)
        .env("KEYCHUTE_TOKEN", "test-token")
        .env("PATH", path_env)
        .env("TMPDIR", tmp_dir)
        .env("HOME", &home_dir)
        .env("FAKE_SSH_CAPTURE_DIR", capture_dir)
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .env_remove("KEYCHUTE_CA_BUNDLE")
        .env_remove("KEYCHUTE_EXTERNAL_URL")
        .env_remove("SSH_AUTH_SOCK");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to execute keychute binary")
}

#[tokio::test]
async fn standard_ed25519_key_loads_into_ephemeral_agent_and_cleans_up() {
    let dir = TempDir::new("kc-ssh-std");
    let (priv_bytes, pub_line) = generate_ed25519_keypair(dir.path());
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: false,
        granted_secret_name: None,
        auto_approved: false,
    })
    .await;

    let capture_clone = capture.clone();
    let tmp_clone = sock_tmp.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &tmp_clone,
            &[("FAKE_SSH_STDOUT", "hello-from-node\n")],
            &[
                "ssh",
                "ansibleadm@grotten",
                "--secret",
                "node-ssh-key",
                "--reason",
                "check k3s status",
                "--timeout",
                "30",
                "--",
                "sudo",
                "systemctl",
                "status",
                "k3s",
            ],
        )
    })
    .await
    .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hello-from-node\n");

    // Private key material never hits stdout or stderr.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE KEY"));
    assert!(!stderr.contains("PRIVATE KEY"));

    // Mock saw cli-read + claimed SSH context.
    let bodies = state.create_bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["secret_name"], "node-ssh-key");
    assert_eq!(bodies[0]["mechanism"], "cli-read");
    assert_eq!(bodies[0]["constraints"]["max_uses"], 1);
    assert_eq!(
        bodies[0]["context"]["structured"]["ssh"]["target"],
        "ssh ansibleadm@grotten -- sudo systemctl status k3s"
    );
    assert_eq!(bodies[0]["context"]["structured"]["ssh"]["host"], "grotten");
    assert_eq!(
        bodies[0]["context"]["structured"]["ssh"]["user"],
        "ansibleadm"
    );
    assert_eq!(bodies[0]["context"]["structured"]["ssh"]["port"], 22);

    // Real ssh-agent held the exact generated public key.
    let agent_keys = std::fs::read_to_string(capture.join("agent_keys")).unwrap();
    assert_eq!(agent_keys.trim(), pub_line);

    // Fake ssh received isolated agent flags + target + remote command.
    let argv: Vec<String> = std::fs::read_to_string(capture.join("argv"))
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    let expected_kh = format!(
        "UserKnownHostsFile={}",
        dir.path().join("home/.ssh/known_hosts").display()
    );
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
            &expected_kh,
            "-o",
            "ConnectTimeout=30",
            "--",
            "ansibleadm@grotten",
            "sudo",
            "systemctl",
            "status",
            "k3s",
        ]
    );

    // Socket directory and socket are cleaned up after exit.
    let sock_path = PathBuf::from(
        std::fs::read_to_string(capture.join("sock_path"))
            .unwrap()
            .trim(),
    );
    assert!(!sock_path.exists(), "socket still exists");
    assert!(
        !sock_path.parent().unwrap().exists(),
        "socket dir still exists"
    );
}

#[tokio::test]
async fn crlf_and_missing_trailing_newline_key_is_normalized_and_loaded() {
    let dir = TempDir::new("kc-ssh-crlf");
    let (priv_bytes, pub_line) = generate_ed25519_keypair(dir.path());
    let text = String::from_utf8(priv_bytes).unwrap();
    let crlf_no_nl = text.trim_end_matches('\n').replace('\n', "\r\n");

    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: crlf_no_nl.into_bytes(),
        deny: false,
        granted_secret_name: None,
        auto_approved: false,
    })
    .await;

    let capture_clone = capture.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &sock_tmp,
            &[],
            &["ssh", "ubnt@router", "--secret", "node-ssh-key"],
        )
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let agent_keys = std::fs::read_to_string(capture.join("agent_keys")).unwrap();
    assert_eq!(agent_keys.trim(), pub_line);
}

#[tokio::test]
async fn nonzero_ssh_exit_propagates_silently_and_cleans_up_agent() {
    let dir = TempDir::new("kc-ssh-exit");
    let (priv_bytes, _pub_line) = generate_ed25519_keypair(dir.path());
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: false,
        granted_secret_name: None,
        auto_approved: true,
    })
    .await;

    let capture_clone = capture.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &sock_tmp,
            &[
                ("FAKE_SSH_EXIT", "42"),
                ("FAKE_SSH_STDERR", "remote command failed"),
            ],
            &[
                "ssh",
                "ansibleadm@take5",
                "--secret",
                "node-ssh-key",
                "--",
                "false",
            ],
        )
    })
    .await
    .unwrap();

    assert_eq!(out.status.code(), Some(42));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("remote command failed"), "{stderr}");
    // Standing policy notice prints on approval; no redundant keychute error on ssh failure.
    assert!(
        stderr.contains("approved automatically by a standing policy"),
        "{stderr}"
    );
    assert!(!stderr.contains("ssh exited"), "{stderr}");

    let sock_path = PathBuf::from(
        std::fs::read_to_string(capture.join("sock_path"))
            .unwrap()
            .trim(),
    );
    assert!(!sock_path.parent().unwrap().exists());
}

#[tokio::test]
async fn denied_request_exits_3_and_never_runs_ssh() {
    let dir = TempDir::new("kc-ssh-deny");
    let (priv_bytes, _) = generate_ed25519_keypair(dir.path());
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: true,
        granted_secret_name: None,
        auto_approved: false,
    })
    .await;

    let capture_clone = capture.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &sock_tmp,
            &[],
            &["ssh", "ansibleadm@grotten", "--secret", "node-ssh-key"],
        )
    })
    .await
    .unwrap();

    assert_eq!(out.status.code(), Some(3));
    assert!(!capture.join("argv").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "{stderr}");
    assert!(stderr.contains("not today"), "{stderr}");
}

#[tokio::test]
async fn invalid_non_key_secret_exits_1_without_leaking_secret_and_cleans_up() {
    let dir = TempDir::new("kc-ssh-badkey");
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: b"super-secret-non-ssh-token".to_vec(),
        deny: false,
        granted_secret_name: Some("wrong-secret".into()),
        auto_approved: false,
    })
    .await;

    let capture_clone = capture.clone();
    let tmp_clone = sock_tmp.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &tmp_clone,
            &[],
            &["ssh", "ansibleadm@grotten", "--secret", "node-ssh-key"],
        )
    })
    .await
    .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(!capture.join("argv").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ssh-add rejected"), "{stderr}");
    assert!(
        stderr.contains("released \"wrong-secret\" in its place"),
        "{stderr}"
    );
    assert!(!stderr.contains("super-secret-non-ssh-token"));
    assert!(
        std::fs::read_dir(&sock_tmp).unwrap().next().is_none(),
        "agent socket directory must be removed after ssh-add failure"
    );
}

#[tokio::test]
async fn preflight_errors_exit_2_with_zero_server_requests() {
    let dir = TempDir::new("kc-ssh-preflight");
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, state) = start_mock(MockConfig {
        secret_payload: b"unused".to_vec(),
        deny: false,
        granted_secret_name: None,
        auto_approved: false,
    })
    .await;

    for bad_args in [
        vec![
            "ssh",
            "grotten",
            "--secret",
            "k",
            "--strict-host-key-checking",
            "no",
        ],
        vec![
            "ssh",
            "grotten",
            "--secret",
            "k",
            "--known-hosts-file",
            "/dev/null",
        ],
        vec![
            "ssh",
            "grotten",
            "--secret",
            "k",
            "--known-hosts-file",
            "none",
        ],
        vec![
            "ssh",
            "grotten",
            "--secret",
            "k",
            "--known-hosts-file",
            "/nonexistent-keychute-dir/kh",
        ],
        vec!["ssh", "grotten", "--secret", "k", "-L", "nonsense"],
        vec!["ssh", "u@grotten", "-l", "other", "--secret", "k"],
    ] {
        let u = url.clone();
        let p = path_env.clone();
        let c = capture.clone();
        let t = sock_tmp.clone();
        let owned: Vec<String> = bad_args.into_iter().map(str::to_string).collect();
        let out = tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            run_ssh_cli(&u, &p, &c, &t, &[], &refs)
        })
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(2));
    }

    // Unwritable/invalid HOME with omitted --known-hosts-file fails locally before contacting Keychute.
    let bad_home = dir.path().join("home-file");
    std::fs::write(&bad_home, "x").unwrap();
    let u2 = url.clone();
    let p2 = path_env.clone();
    let c2 = capture.clone();
    let t2 = sock_tmp.clone();
    let bad_home_str = bad_home.display().to_string();
    let out_home = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &u2,
            &p2,
            &c2,
            &t2,
            &[("HOME", &bad_home_str)],
            &["ssh", "grotten", "--secret", "k"],
        )
    })
    .await
    .unwrap();
    assert_eq!(out_home.status.code(), Some(2));

    // Missing OpenSSH binaries on PATH also fails locally before contacting Keychute.
    let empty_bin = dir.path().join("empty-bin");
    std::fs::create_dir_all(&empty_bin).unwrap();
    let u = url.clone();
    let empty_path = empty_bin.display().to_string();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &u,
            &empty_path,
            &capture,
            &sock_tmp,
            &[],
            &["ssh", "grotten", "--secret", "k"],
        )
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        state.create_bodies.lock().unwrap().is_empty(),
        "preflight errors must never send an access request"
    );
}

#[tokio::test]
async fn implicit_user_is_resolved_and_bound_in_context_and_argv() {
    let dir = TempDir::new("kc-ssh-impuser");
    let (priv_bytes, _) = generate_ed25519_keypair(dir.path());
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: false,
        granted_secret_name: None,
        auto_approved: true,
    })
    .await;

    let capture_clone = capture.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &sock_tmp,
            &[],
            &["ssh", "grotten", "--secret", "node-ssh-key"],
        )
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bodies = state.create_bodies.lock().unwrap().clone();
    let user = bodies[0]["context"]["structured"]["ssh"]["user"]
        .as_str()
        .expect("resolved default login user must be attached");
    assert!(!user.is_empty());

    let argv: Vec<String> = std::fs::read_to_string(capture.join("argv"))
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    assert!(
        argv.windows(2).any(|w| w == ["-l", user]),
        "expected `-l {user}` in ssh argv: {argv:?}"
    );
}

#[cfg(unix)]
async fn assert_signal_stops_ssh_and_cleans_up(sig_flag: &str, expected_code: i32, prefix: &str) {
    let dir = TempDir::new(prefix);
    let (priv_bytes, _) = generate_ed25519_keypair(dir.path());
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    let home_dir = dir.path().join("home");
    std::fs::create_dir_all(&sock_tmp).unwrap();
    std::fs::create_dir_all(&home_dir).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: false,
        granted_secret_name: None,
        auto_approved: true,
    })
    .await;

    let child = Command::new(env!("CARGO_BIN_EXE_keychute"))
        .args(["ssh", "ansibleadm@grotten", "--secret", "node-ssh-key"])
        .env("KEYCHUTE_URL", &url)
        .env("KEYCHUTE_TOKEN", "test-token")
        .env("PATH", &path_env)
        .env("TMPDIR", &sock_tmp)
        .env("HOME", &home_dir)
        .env("FAKE_SSH_CAPTURE_DIR", &capture)
        .env("FAKE_SSH_SLEEP", "30")
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .env_remove("KEYCHUTE_CA_BUNDLE")
        .env_remove("KEYCHUTE_EXTERNAL_URL")
        .env_remove("SSH_AUTH_SOCK")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn keychute");

    let ready = capture.join("ready");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for fake ssh to start"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let sock_path = std::fs::read_to_string(capture.join("sock_path"))
        .unwrap()
        .trim()
        .to_string();
    assert!(
        Path::new(&sock_path).exists(),
        "agent socket must exist while ssh runs: {sock_path}"
    );

    let kill_status = Command::new("kill")
        .args([sig_flag, &child.id().to_string()])
        .status()
        .expect("failed running kill");
    assert!(kill_status.success());

    let out = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(expected_code));
    assert!(
        !Path::new(&sock_path).exists(),
        "ephemeral agent socket must be removed on {sig_flag}: {sock_path}"
    );
    assert!(
        std::fs::read_dir(&sock_tmp).unwrap().next().is_none(),
        "agent socket directory must be removed on {sig_flag}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_terminates_ssh_and_cleans_up_ephemeral_agent() {
    assert_signal_stops_ssh_and_cleans_up("-HUP", 129, "kc-ssh-sighup").await;
}

#[cfg(unix)]
#[tokio::test]
async fn sigint_targeted_at_keychute_stops_ssh_and_cleans_up_agent() {
    assert_signal_stops_ssh_and_cleans_up("-INT", 130, "kc-ssh-sigint").await;
}

#[tokio::test]
async fn encrypted_key_fails_fast_without_prompting_and_cleans_up() {
    let dir = TempDir::new("kc-ssh-enc");
    let (priv_bytes, _) = generate_ed25519_keypair_with_passphrase(dir.path(), "pass123");
    let (_bin, capture, path_env) = install_fake_ssh(dir.path());
    let sock_tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&sock_tmp).unwrap();

    let (url, _state) = start_mock(MockConfig {
        secret_payload: priv_bytes,
        deny: false,
        granted_secret_name: None,
        auto_approved: true,
    })
    .await;

    let capture_clone = capture.clone();
    let tmp_clone = sock_tmp.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_ssh_cli(
            &url,
            &path_env,
            &capture_clone,
            &tmp_clone,
            &[],
            &["ssh", "ansibleadm@grotten", "--secret", "node-ssh-key"],
        )
    })
    .await
    .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(!capture.join("argv").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ssh-add rejected"), "{stderr}");
    assert!(
        std::fs::read_dir(&sock_tmp).unwrap().next().is_none(),
        "agent socket directory must be removed after encrypted-key failure"
    );
}
