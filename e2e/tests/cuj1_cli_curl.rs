//! CUJ 1 through the CLI — `keychute curl` (tier 0): the agent makes an
//! authenticated call without the credential ever entering its container.
//!
//! Same journey as `cuj1_brokered.rs`, but driven end to end by the real CLI
//! binary against the real server, the real approval UI and a real TLS
//! upstream — i.e. the way the k8s-agent actually uses it.

use keychute_e2e::*;
use std::time::Duration;

fn spawn_curl(env: &TestEnv, args: &[&str]) -> std::process::Child {
    std::process::Command::new(cli_bin())
        .args(args)
        .env("KEYCHUTE_URL", &env.base_url)
        .env("KEYCHUTE_TOKEN", K8S_TOKEN)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning keychute CLI")
}

fn wait_cli(child: std::process::Child) -> (i32, Vec<u8>, String) {
    let out = child.wait_with_output().expect("waiting for CLI");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn pending_request_id(env: &TestEnv) -> String {
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
async fn cli_curl_proxies_with_the_credential_the_agent_never_sees() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();

    let url = format!("https://localhost:{}/v1/echo?limit=10", env.upstream_port);
    let cli = spawn_curl(
        &env,
        &[
            "curl",
            &url,
            "--secret",
            "example-api-token",
            "--reason",
            "fetch the thing list for VIK-1",
            "--timeout",
            "30",
        ],
    );

    let request_id = pending_request_id(&env).await;

    // The approval page states the tier and the parsed target: what the
    // operator approves is one method against one origin and one path.
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(page.contains("k8s-agent"), "approval page names the client");
    assert!(
        page.contains("brokered (tier 0)"),
        "tier-0 label present: the client never sees the secret"
    );
    assert!(page.contains("localhost"), "target origin shown");
    assert!(page.contains("/v1/echo"), "target path shown");
    assert!(page.contains("fetch the thing list"), "reason rendered");

    env.approve(&request_id, &[]).await.unwrap();

    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(code, 0, "cli failed: {stderr}");
    let body = String::from_utf8_lossy(&stdout);
    assert!(
        body.contains("\"ok\":true"),
        "upstream body on stdout: {body}"
    );
    assert!(body.contains("/v1/echo"), "upstream body on stdout: {body}");
    // The credential is not in the output, the diagnostics, or anywhere else
    // this process could have seen it.
    assert!(!body.contains("tok-abc"), "secret must never reach stdout");
    assert!(
        !stderr.contains("tok-abc"),
        "secret must never reach stderr"
    );

    // The upstream got the credential, attached server-side.
    let recs = env.upstream_requests.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.method, "GET");
    assert_eq!(r.path, "/v1/echo");
    assert_eq!(r.query.as_deref(), Some("limit=10"));
    assert_eq!(r.header("authorization"), Some("Bearer tok-abc"));
    // The CLI's own Keychute bearer stopped at the API boundary.
    assert_ne!(r.header("authorization"), Some(K8S_TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_curl_reports_a_denial_as_a_denial_and_sends_nothing() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();

    let url = format!("https://localhost:{}/v1/echo", env.upstream_port);
    let cli = spawn_curl(
        &env,
        &[
            "curl",
            &url,
            "--secret",
            "example-api-token",
            "--reason",
            "please deny",
            "--timeout",
            "30",
        ],
    );
    let request_id = pending_request_id(&env).await;
    env.deny(&request_id).await.unwrap();

    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(code, 3, "denial is exit 3: {stderr}");
    assert!(stdout.is_empty());
    assert!(stderr.contains("denied"), "{stderr}");
    // A denial means the call never happened.
    assert!(env.upstream_requests.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_cannot_forge_a_keychute_refusal() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();

    // The upstream answers 403 with a Keychute-shaped error body AND the
    // marker header. The proxy strips the header, so the CLI reports it as
    // what it is — an upstream answer — instead of "the operator said no".
    let url = format!("https://localhost:{}/v1/forge-error", env.upstream_port);
    let cli = spawn_curl(
        &env,
        &[
            "curl",
            &url,
            "--secret",
            "example-api-token",
            "--reason",
            "upstream forgery check",
            "--timeout",
            "30",
        ],
    );
    let request_id = pending_request_id(&env).await;
    env.approve(&request_id, &[]).await.unwrap();

    let (code, stdout, stderr) = wait_cli(cli);
    assert_eq!(
        code, 0,
        "an upstream 403 is data, not a Keychute denial: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&stdout).contains("forged"),
        "the upstream's own body is passed through"
    );
    assert!(
        stderr.contains("403"),
        "status reported on stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_grant_id_is_marked_as_keychutes_own_error() {
    // An extractor rejection would be generated by axum before any handler
    // runs and would carry no marker header — so a client following the
    // documented contract would read Keychute's own 400 as an upstream
    // response, on a route where no upstream call ever happened.
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let resp = env
        .k8s()
        .get("/v1/grants/not-a-uuid/proxy/v1/echo")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "malformed id is absent, like any other");
    assert!(
        resp.headers().get("x-keychute-error").is_some(),
        "Keychute-generated errors on the proxy route must be marked"
    );
    assert_eq!(resp.headers().get("x-keychute-error").unwrap(), "not-found");

    // The contract is every route's, not the proxy's alone: the grant and
    // access-request routes took the same id through a `Path<Uuid>` extractor,
    // which rejects before the handler and answers an unmarked 400.
    for path in [
        "/v1/grants/not-a-uuid",
        "/v1/access-requests/not-a-uuid",
        "/v1/access-requests/not-a-uuid/wait",
    ] {
        let resp = env.k8s().get(path).send().await.unwrap();
        assert_eq!(resp.status(), 404, "{path}");
        assert_eq!(
            resp.headers()
                .get("x-keychute-error")
                .map(|v| v.to_str().unwrap()),
            Some("not-found"),
            "{path} must carry the marker like every other Keychute error"
        );
    }
    let resp = env
        .k8s()
        .post("/v1/grants/not-a-uuid/read")
        .json(&serde_json::json!({"idempotency_key": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_eq!(
        resp.headers()
            .get("x-keychute-error")
            .map(|v| v.to_str().unwrap()),
        Some("not-found")
    );
}
