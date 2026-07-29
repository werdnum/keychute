//! Client-initiated secret deposit: `keychute store` (`POST /v1/secrets`).
//!
//! The deposit path is the one client write that carries credential bytes INTO
//! Keychute, so these tests pin its guardrails as much as its happy path: the
//! config opt-in, create-only (never a rotation), and the tier cap.

use keychute_e2e::*;
use std::io::Write;
use std::time::Duration;

/// Run the CLI as a child process with `stdin` fed from `input`; returns
/// (exit code, stdout bytes, stderr).
fn run_cli_with_stdin(env: &TestEnv, args: &[&str], input: &[u8]) -> (i32, Vec<u8>, String) {
    let mut child = std::process::Command::new(cli_bin())
        .args(args)
        .env("KEYCHUTE_URL", &env.base_url)
        .env("KEYCHUTE_TOKEN", K8S_TOKEN)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning keychute CLI");
    child
        .stdin
        .as_mut()
        .expect("cli stdin")
        .write_all(input)
        .expect("writing secret to cli stdin");
    let out = child.wait_with_output().expect("waiting for CLI");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn spawn_request_cli(env: &TestEnv, args: &[&str]) -> std::process::Child {
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

/// The full agent journey: deposit a credential it just minted, then get it
/// back through the normal approval flow — proving the deposited bytes are
/// what a later release returns, trailing shell newline and all.
#[tokio::test(flavor = "multi_thread")]
async fn cli_stores_a_new_secret_and_it_releases_intact() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // `echo secret | keychute store …`: the trailing newline is shell noise.
    let (code, stdout, stderr) = run_cli_with_stdin(
        &env,
        &[
            "store",
            "minted-api-key",
            "--description",
            "minted by the agent",
            "--max-tier",
            "cooperating-client",
        ],
        b"s3kr1t-value\n",
    );
    assert_eq!(code, 0, "store failed: {stderr}");
    assert!(stdout.is_empty(), "store writes nothing to stdout");
    assert!(
        stderr.contains("stored minted-api-key"),
        "store confirmation on stderr: {stderr}"
    );
    assert!(
        !stderr.contains("s3kr1t-value"),
        "the value must never be echoed: {stderr}"
    );

    // The operator sees it in the UI...
    let page = env.ui_get("/ui/secrets").await.unwrap();
    assert!(page.contains("minted-api-key"), "secret listed in the UI");
    assert!(page.contains("minted by the agent"), "description shown");

    // ...and was pushed about it, in server vocabulary only.
    let forms = poll_until("deposit push", Duration::from_secs(15), || async {
        let forms = env.pushover_forms.lock().unwrap().clone();
        (!forms.is_empty()).then_some(forms)
    })
    .await;
    let msg = forms[0].get("message").cloned().unwrap_or_default();
    assert!(msg.contains("k8s-agent"), "push names the client: {msg}");
    assert!(
        msg.contains("minted-api-key"),
        "push names the secret: {msg}"
    );
    assert!(
        !msg.contains("s3kr1t-value"),
        "push must never carry the value: {msg}"
    );

    // Releasing it still needs an approval — and returns exactly the bytes
    // that were deposited, with the shell newline stripped.
    let cli = spawn_request_cli(&env, &["request", "minted-api-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(
        !page.contains("NOT stored in Keychute"),
        "the deposit made this a stored secret"
    );
    env.approve(&request_id, &[]).await.unwrap();
    let out = cli.wait_with_output().expect("waiting for CLI");
    assert_eq!(
        out.status.code(),
        Some(0),
        "request failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"s3kr1t-value");
}

/// `--raw` keeps the bytes verbatim, for credentials whose trailing newline
/// is real (a PEM block).
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_raw_keeps_the_trailing_newline() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let (code, _, stderr) = run_cli_with_stdin(&env, &["store", "pem-key", "--raw"], b"line-one\n");
    assert_eq!(code, 0, "store failed: {stderr}");
    assert!(
        !stderr.contains("stripped the trailing newline"),
        "--raw strips nothing: {stderr}"
    );

    let version: i32 =
        sqlx::query_scalar("SELECT current_version FROM secrets WHERE name = 'pem-key'")
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(version, 1);
}

/// Create-only: a deposit never replaces credential bytes an operator already
/// reviewed, so an existing name is a conflict and the stored value is left
/// exactly as it was.
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_refuses_to_replace_an_existing_secret() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret(
        "existing-key",
        "operator-value",
        "cooperating-client",
        "bearer",
        "",
    )
    .await
    .unwrap();

    let (code, _, stderr) = run_cli_with_stdin(
        &env,
        &["store", "existing-key", "--max-tier", "cooperating-client"],
        b"agent-value\n",
    );
    assert_eq!(code, 1, "conflict is the generic failure code: {stderr}");
    assert!(
        stderr.contains("already exists"),
        "conflict explained: {stderr}"
    );
    assert!(
        stderr.contains("rotation"),
        "the remediation is named: {stderr}"
    );

    // No new version: the operator's bytes survive untouched.
    let version: i32 =
        sqlx::query_scalar("SELECT current_version FROM secrets WHERE name = 'existing-key'")
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(version, 1, "the deposit must not have rotated the secret");

    // And the release path still returns the operator's value.
    let cli = spawn_request_cli(&env, &["request", "existing-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;
    env.approve(&request_id, &[]).await.unwrap();
    let out = cli.wait_with_output().expect("waiting for CLI");
    assert_eq!(out.stdout, b"operator-value");
}

/// A deposit may not out-rank its depositor: k8s-agent is capped at tier 2.
#[tokio::test(flavor = "multi_thread")]
async fn cli_store_rejects_a_tier_above_the_client_cap() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let (code, _, stderr) = run_cli_with_stdin(
        &env,
        &["store", "too-hot", "--max-tier", "direct"],
        b"value\n",
    );
    assert_eq!(code, 1, "rejected: {stderr}");
    assert!(
        stderr.contains("max_tier exceeds"),
        "reason surfaced: {stderr}"
    );

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE name = 'too-hot'")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(count, 0, "nothing was stored");
}

/// The endpoint is opt-in per client: family-assistant has no
/// `may_store_secrets`, so its deposit is refused like any policy denial.
#[tokio::test(flavor = "multi_thread")]
async fn client_without_the_opt_in_may_not_store() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let resp = env
        .fa()
        .post("/v1/secrets")
        .json(&serde_json::json!({
            "name": "fa-deposit",
            "value": "nope",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "policy-denied");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE name = 'fa-deposit'")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(count, 0, "nothing was stored");
}

/// Names are echoed in pushes and typed by operators: keep them boring, and
/// never let one forge structure in a notification.
#[tokio::test(flavor = "multi_thread")]
async fn store_rejects_hostile_names_and_oversize_values() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    for bad in ["with space", "line\nbreak", ""] {
        let resp = env
            .k8s()
            .post("/v1/secrets")
            .json(&serde_json::json!({"name": bad, "value": "v"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "name {bad:?} must be rejected");
    }

    let resp = env
        .k8s()
        .post("/v1/secrets")
        .json(&serde_json::json!({
            "name": "huge",
            "value": "x".repeat(200 * 1024),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "request-too-large");
}

/// Binary credentials survive the round trip via base64.
#[tokio::test(flavor = "multi_thread")]
async fn store_accepts_base64_for_non_utf8_values() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // 0xff 0x00 0xfe is not valid UTF-8; the CLI picks base64 for it.
    let (code, _, stderr) = run_cli_with_stdin(
        &env,
        &[
            "store",
            "binary-key",
            "--max-tier",
            "cooperating-client",
            "--raw",
        ],
        &[0xff, 0x00, 0xfe],
    );
    assert_eq!(code, 0, "store failed: {stderr}");

    let cli = spawn_request_cli(&env, &["request", "binary-key", "--timeout", "30"]);
    let request_id = wait_pending_request_id(&env).await;
    env.approve(&request_id, &[]).await.unwrap();
    let out = cli.wait_with_output().expect("waiting for CLI");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, vec![0xff, 0x00, 0xfe]);
}

/// The deposit rate cap: an opted-in client that runs away cannot bury the
/// operator in pushes and rows.
#[tokio::test(flavor = "multi_thread")]
async fn deposits_are_rate_capped_per_client() {
    let env = TestEnv::spawn(SpawnOpts {
        max_deposits_per_hour_per_client: 2,
        ..SpawnOpts::default()
    })
    .await
    .unwrap();

    for i in 0..2 {
        let resp = env
            .k8s()
            .post("/v1/secrets")
            .json(&serde_json::json!({"name": format!("dep-{i}"), "value": "v"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "deposit {i} should succeed");
    }

    let resp = env
        .k8s()
        .post("/v1/secrets")
        .json(&serde_json::json!({"name": "dep-over", "value": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "too-many-deposits");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE name = 'dep-over'")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// A deposit must not be able to unlock a standing auto-approve row. The
/// depositing client picks the name, so without the unvetted clamp it could
/// create a secret matching a policy the operator wrote for a credential THEY
/// intended to store, and have its own bytes released with nobody in the loop.
#[tokio::test(flavor = "multi_thread")]
async fn a_deposit_cannot_satisfy_a_standing_auto_approve_policy() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // The operator has a standing auto-approve for a name nothing is stored
    // under yet — today that clamps to require-approval because the secret
    // does not exist.
    env.create_policy(&[
        ("client_name", "k8s-agent"),
        ("secret_name", "reserved-name"),
        ("mechanism", "cli-read"),
        ("outcome", "auto-approve"),
        ("priority", "0"),
        ("max_ttl_seconds", "3600"),
    ])
    .await
    .unwrap();

    // The client deposits under exactly that name...
    let (code, _, stderr) = run_cli_with_stdin(
        &env,
        &["store", "reserved-name", "--max-tier", "cooperating-client"],
        b"client-chosen\n",
    );
    assert_eq!(code, 0, "store failed: {stderr}");

    // ...and a matching request STILL waits for a human: the secret exists,
    // but no operator has reviewed the bytes.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("dep-1", "reserved-name", 60, "please"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["state"], "pending",
        "an unreviewed deposit must not auto-approve: {body}"
    );
    assert!(body["grant_id"].is_null(), "no grant was minted: {body}");

    // The approval page tells the operator where those bytes came from.
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(
        page.contains("not yet reviewed by you"),
        "approval page flags the unreviewed deposit"
    );

    // Once the operator marks it reviewed, the standing policy applies again.
    let secrets_page = env.ui_get("/ui/secrets").await.unwrap();
    let secret_id: String =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM secrets WHERE name = 'reserved-name'")
            .fetch_one(&env.db)
            .await
            .unwrap()
            .to_string();
    assert!(
        secrets_page.contains("Mark reviewed"),
        "the secrets page offers the review action"
    );
    let action = format!("/ui/secrets/{secret_id}/reviewed");
    let token = extract_csrf(&secrets_page, &action).expect("review csrf token");
    let (status, body) = env
        .ui_post(&action, &[("csrf_token", &token)])
        .await
        .unwrap();
    assert!(
        status.is_redirection(),
        "mark reviewed failed: {status} {body}"
    );

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("dep-2", "reserved-name", 60, "please"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["state"], "approved",
        "a reviewed secret follows the standing policy again: {body}"
    );
}
