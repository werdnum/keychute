//! CUJ 2c — `keychute ssh` (tier-2 cli-read with ephemeral local `ssh-agent`)
//! exercised end to end through the real CLI binary, real server, and approval UI.

use keychute_e2e::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn generate_ed25519_keypair(dir: &Path) -> (String, String) {
    let key_path = dir.join("e2e_ed25519");
    let pub_path = dir.join("e2e_ed25519.pub");
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "e2e-ssh", "-f"])
        .arg(&key_path)
        .output()
        .expect("ssh-keygen must be installed");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let priv_pem = std::fs::read_to_string(&key_path).unwrap();
    let pub_line = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_path);
    (priv_pem, pub_line)
}

fn install_fake_ssh(root: &Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let bin_dir = root.join("bin");
    let capture_dir = root.join("capture");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&capture_dir).unwrap();

    let shim = bin_dir.join("ssh");
    let script = r#"#!/bin/sh
set -eu
test -n "${SSH_AUTH_SOCK:-}"
test -S "${SSH_AUTH_SOCK}"
ssh-add -L > "${FAKE_SSH_CAPTURE_DIR}/agent_keys"
printf '%s\n' "$@" > "${FAKE_SSH_CAPTURE_DIR}/argv"
printf 'ssh-ok\n'
"#;
    std::fs::write(&shim, script).unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let path_env = format!("{}:{existing_path}", bin_dir.display());
    (bin_dir, capture_dir, path_env)
}

async fn wait_pending_request_id(env: &TestEnv) -> String {
    poll_until(
        "pending request on /ui/requests",
        Duration::from_secs(15),
        || async {
            let page = env.ui_get("/ui/requests").await.ok()?;
            extract_request_ids(&page).into_iter().next()
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_ssh_shows_claimed_session_and_loads_key_into_ephemeral_agent() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (priv_pem, pub_line) = generate_ed25519_keypair(tmp.path());
    // Simulate a key pasted into the approval textarea (CRLF, no trailing LF).
    let textarea_pem = priv_pem.trim_end_matches('\n').replace('\n', "\r\n");
    let (_bin, capture, path_env) = install_fake_ssh(tmp.path());

    let cli = Command::new(cli_bin())
        .args([
            "ssh",
            "ansibleadm@grotten",
            "--secret",
            "node-ssh-key",
            "--reason",
            "inspect k3s logs",
            "--timeout",
            "30",
            "--",
            "sudo",
            "journalctl",
            "-u",
            "k3s",
        ])
        .env("KEYCHUTE_URL", &env.base_url)
        .env("KEYCHUTE_TOKEN", K8S_TOKEN)
        .env("PATH", &path_env)
        .env("FAKE_SSH_CAPTURE_DIR", &capture)
        .env_remove("SSH_AUTH_SOCK")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning keychute CLI");

    let request_id = wait_pending_request_id(&env).await;
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(page.contains("SSH session claimed by the client"), "{page}");
    assert!(
        page.contains("ssh ansibleadm@grotten -- sudo journalctl -u k3s"),
        "{page}"
    );
    assert!(page.contains("ephemeral local ssh-agent"), "{page}");

    env.approve(&request_id, &[("secret_value", &textarea_pem)])
        .await
        .unwrap();

    let out = cli.wait_with_output().expect("waiting for CLI");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "cli failed: {stderr}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ssh-ok\n");
    assert!(!stderr.contains("PRIVATE KEY"));

    let loaded_keys = std::fs::read_to_string(capture.join("agent_keys")).unwrap();
    assert_eq!(loaded_keys.trim(), pub_line);

    let rid: uuid::Uuid = request_id.parse().unwrap();
    let want = [
        "request-created",
        "request-approved",
        "release-attempt",
        "release-completed",
    ];
    let kinds = env.wait_for_audit_kinds(rid, &want).await;
    for k in want {
        assert!(
            kinds.contains(&k.to_owned()),
            "missing audit {k}: {kinds:?}"
        );
    }
}
