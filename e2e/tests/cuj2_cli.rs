//! CUJ 2 — the core journey: `keychute request` (tier-2 cli-read) with a
//! human approval in the loop, exercised through the real CLI binary.

use keychute_e2e::*;
use std::time::Duration;

/// Run the CLI `request` subcommand as a child process; returns
/// (exit code, stdout bytes, stderr).
fn spawn_cli(env: &TestEnv, args: &[&str]) -> std::process::Child {
    std::process::Command::new(cli_bin())
        .args(args)
        .env("KEYCHUTE_URL", &env.base_url)
        .env("KEYCHUTE_TOKEN", K8S_TOKEN)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning keychute CLI")
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

fn wait_cli(child: std::process::Child) -> (i32, Vec<u8>, String) {
    let out = child.wait_with_output().expect("waiting for CLI");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_request_approved_with_passthrough_secret() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let cli = spawn_cli(
        &env,
        &[
            "request",
            "my-api-key",
            "--reason",
            "seal into ns",
            "--timeout",
            "30",
        ],
    );

    // The request appears on the pending list.
    let request_id = wait_pending_request_id(&env).await;

    // Approval page shows the client, the tier-2 caveat, and the reason.
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(page.contains("k8s-agent"), "approval page names the client");
    assert!(page.contains("Tier-2 caveat"), "tier-2 caveat present");
    assert!(
        page.contains("cooperating-client (tier 2)"),
        "tier label present"
    );
    assert!(page.contains("seal into ns"), "client reason rendered");
    assert!(
        page.contains("NOT stored in Keychute"),
        "unknown secret flagged for value entry"
    );

    // Approve with a passthrough secret value (store_secret unchecked).
    env.approve(&request_id, &[("secret_value", "s3kr1t-value")])
        .await
        .unwrap();

    // CLI exits 0 and stdout is exactly the secret bytes (no trailing newline
    // when stdout is a pipe).
    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(code, 0, "cli failed: {stderr}");
    assert_eq!(stdout, b"s3kr1t-value");

    // Push vocabulary: generic label for an unknown secret, never the name or
    // the client reason (addendum #5).
    let forms = env.pushover_forms.lock().unwrap().clone();
    assert!(!forms.is_empty(), "an approval push was sent");
    for f in &forms {
        let msg = f.get("message").cloned().unwrap_or_default();
        assert!(
            !msg.contains("my-api-key"),
            "push must not name an unstored secret: {msg}"
        );
        assert!(
            !msg.contains("seal into ns"),
            "push must not carry client context: {msg}"
        );
        assert!(
            msg.contains("a not-yet-stored secret"),
            "generic label: {msg}"
        );
        assert!(
            msg.contains("k8s-agent"),
            "client name is server vocabulary"
        );
    }

    // Audit trail: created → approved → release-attempt → release-completed.
    let rid: uuid::Uuid = request_id.parse().unwrap();
    let kinds = env.audit_kinds_for_request(rid).await;
    for want in [
        "request-created",
        "request-approved",
        "release-attempt",
        "release-completed",
    ] {
        assert!(
            kinds.contains(&want.to_owned()),
            "missing audit {want}: {kinds:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_request_with_store_secret_then_named_push() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let cli = spawn_cli(&env, &["request", "my-api-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;

    // Approve WITH storage this time (cooperating-client tier so cli-read
    // stays within the stored secret's cap).
    env.approve(
        &request_id,
        &[
            ("secret_value", "stored-secret-v1"),
            ("store_secret", "on"),
            ("store_max_tier", "cooperating-client"),
        ],
    )
    .await
    .unwrap();

    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(code, 0, "cli failed: {stderr}");
    assert_eq!(stdout, b"stored-secret-v1");

    // The secret now exists in the admin UI.
    let secrets = env.ui_get("/ui/secrets").await.unwrap();
    assert!(secrets.contains("my-api-key"), "stored secret listed");

    // A second request for the same secret pushes with the REAL name now.
    let pushes_before = env.pushover_forms.lock().unwrap().len();
    let cli2 = spawn_cli(&env, &["request", "my-api-key", "--timeout", "30"]);
    poll_until("second push", Duration::from_secs(15), || async {
        (env.pushover_forms.lock().unwrap().len() > pushes_before).then_some(())
    })
    .await;
    let forms = env.pushover_forms.lock().unwrap().clone();
    let last = forms.last().unwrap();
    let msg = last.get("message").cloned().unwrap_or_default();
    assert!(
        msg.contains("my-api-key"),
        "stored secret name in push: {msg}"
    );

    // Approve (no value needed — the secret is stored) and let the CLI finish.
    let request_id2 = wait_pending_request_id(&env).await;
    env.approve(&request_id2, &[]).await.unwrap();
    let (code, stdout, stderr) = wait_cli(cli2);
    assert_eq!(code, 0, "cli2 failed: {stderr}");
    assert_eq!(stdout, b"stored-secret-v1");
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_denied_request_exits_3() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let cli = spawn_cli(&env, &["request", "nope-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;
    env.deny(&request_id).await.unwrap();
    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(code, 3, "denied → exit 3; stderr: {stderr}");
    assert!(stdout.is_empty(), "no secret bytes on deny");
}

/// SLOW (sweeper-dependent): after the read, the passthrough ciphertext is
/// purged once the replay window closes and the 30s sweep runs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: waits for the 30s sweeper to purge the passthrough payload"]
async fn passthrough_ciphertext_purged_after_replay_window() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let cli = spawn_cli(&env, &["request", "purge-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;
    env.approve(&request_id, &[("secret_value", "purge-me")])
        .await
        .unwrap();
    let (code, stdout, _stderr) = wait_cli(cli);
    assert_eq!(code, 0);
    assert_eq!(stdout, b"purge-me");

    // The payload exists right after the read...
    let (ct,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT passthrough_ciphertext FROM grants WHERE request_id = $1")
            .bind(request_id.parse::<uuid::Uuid>().unwrap())
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert!(ct.is_some(), "payload present immediately after read");

    // ...and is nulled by the sweeper once the 3s replay window closes.
    let rid = request_id.parse::<uuid::Uuid>().unwrap();
    poll_until("passthrough purge", Duration::from_secs(75), || async {
        let (ct,): (Option<Vec<u8>>,) =
            sqlx::query_as("SELECT passthrough_ciphertext FROM grants WHERE request_id = $1")
                .bind(rid)
                .fetch_one(&env.db)
                .await
                .unwrap();
        ct.is_none().then_some(())
    })
    .await;
}
