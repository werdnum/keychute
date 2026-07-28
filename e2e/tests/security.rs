//! Security properties: authn, tier/mechanism caps, deny policies,
//! idempotency, expiry, revocation, revalidation, UI CSRF, ownership.

use keychute_e2e::*;

#[tokio::test(flavor = "multi_thread")]
async fn authn_and_mechanism_caps() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // No credentials → 401.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/access-requests", env.base_url))
        .json(&cli_read_request("x", "s", 60, ""))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token → uniform 401.
    let (status, body) = env
        .client("not-a-real-token")
        .create_request(cli_read_request("x", "s", 60, ""))
        .await
        .unwrap();
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"]["code"], "unauthenticated");

    // k8s-agent may only use cli-read: a brokered request is denied.
    let (status, body) = env
        .k8s()
        .create_request(brokered_request(
            "k8s-brokered",
            "some-secret",
            "localhost",
            443,
            &["GET"],
            &["/v1"],
            60,
        ))
        .await
        .unwrap();
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "policy-denied");

    // family-assistant (max_tier trusted-client, mechanisms brokered+autofill)
    // may not use cli-read.
    let (status, body) = env
        .fa()
        .create_request(cli_read_request("fa-cli", "some-secret", 60, "why"))
        .await
        .unwrap();
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "policy-denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_policy_short_circuits_with_audit() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.create_policy(&[
        ("secret_name", "forbidden-secret"),
        ("mechanism", "cli-read"),
        ("outcome", "deny"),
        ("priority", "10"),
    ])
    .await
    .unwrap();

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("deny-1", "forbidden-secret", 60, "pls"))
        .await
        .unwrap();
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["code"], "policy-denied");

    // The request row is denied and audited.
    let row: Option<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, state FROM access_requests WHERE secret_name = 'forbidden-secret'",
    )
    .fetch_optional(&env.db)
    .await
    .unwrap();
    let (rid, state) = row.expect("request row recorded");
    assert_eq!(state, "denied");
    let kinds = env.audit_kinds_for_request(rid).await;
    assert!(
        kinds.contains(&"request-denied".to_owned()),
        "audit request-denied: {kinds:?}"
    );
    // No push for an immediately denied request.
    assert!(env.pushover_forms.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn idempotent_create_dedups_and_conflicts() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let body = cli_read_request("same-key", "idem-secret", 120, "first");
    let (status, first) = env.k8s().create_request(body.clone()).await.unwrap();
    assert_eq!(status, 201, "{first}");
    let rid = first["request_id"].as_str().unwrap().to_owned();

    // Retry with the same key + same payload: 200 with the SAME request id.
    let (status, second) = env.k8s().create_request(body).await.unwrap();
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["request_id"], rid.as_str());

    // Exactly one push despite two creates.
    assert_eq!(env.pushover_forms.lock().unwrap().len(), 1);

    // Same key, different payload → 409.
    let (status, third) = env
        .k8s()
        .create_request(cli_read_request("same-key", "idem-secret", 999, "changed"))
        .await
        .unwrap();
    assert_eq!(status, 409, "{third}");
    assert_eq!(third["error"]["code"], "idempotency-key-reuse");
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_request_cannot_be_approved() {
    let opts = SpawnOpts {
        request_expiry_seconds: 2,
        ..SpawnOpts::default()
    };
    let env = TestEnv::spawn(opts).await.unwrap();

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("exp-1", "expiring-secret", 60, "hurry"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    // Grab a CSRF token while the request is still live, then let it expire.
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    let token = extract_csrf(&page, &format!("/ui/requests/{request_id}/approve"))
        .expect("approve form present before expiry");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let (status, _body) = env
        .ui_post(
            &format!("/ui/requests/{request_id}/approve"),
            &[("csrf_token", &token), ("secret_value", "too-late")],
        )
        .await
        .unwrap();
    assert_eq!(status, 409, "approve after expiry must fail");

    // No grant row was created.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM grants WHERE request_id = $1")
        .bind(request_id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_grant_and_disabled_client_are_refused() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // -- Revocation ---------------------------------------------------------
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("rev-1", "revocable", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[("secret_value", "revoke-me")])
        .await
        .unwrap();
    let st: serde_json::Value = env
        .k8s()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = st["grant_id"].as_str().unwrap().to_owned();

    env.revoke(&grant_id).await.unwrap();
    let (status, body) = env
        .k8s()
        .read_grant(&grant_id, "post-revoke")
        .await
        .unwrap();
    assert_eq!(status, 410, "{body}");
    assert_eq!(body["error"]["code"], "grant-expired");

    // -- Disabled client mid-grant (addendum #15) ---------------------------
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("dis-1", "disable-me", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[("secret_value", "never-released")])
        .await
        .unwrap();
    let st: serde_json::Value = env
        .k8s()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = st["grant_id"].as_str().unwrap().to_owned();

    sqlx::query("UPDATE clients SET enabled = false WHERE name = 'k8s-agent'")
        .execute(&env.db)
        .await
        .unwrap();
    let resp = env
        .k8s()
        .post(&format!("/v1/grants/{grant_id}/read"))
        .json(&serde_json::json!({ "idempotency_key": "after-disable" }))
        .send()
        .await
        .unwrap();
    // Disabled clients fail authentication outright (uniform 401); any of
    // 401/403/404/410 would be an acceptable refusal — 200 would be the bug.
    assert!(
        matches!(resp.status().as_u16(), 401 | 403 | 404 | 410),
        "disabled client must be refused, got {}",
        resp.status()
    );
    let body = resp.text().await.unwrap();
    assert!(!body.contains("never-released"), "no secret bytes: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_requires_auth_csrf_and_same_origin() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // UI without the operator token → 401.
    let resp = reqwest::Client::new()
        .get(format!("{}/ui/requests", env.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Pending request to act on.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("csrf-1", "csrf-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    // Valid operator token but garbage CSRF token → 403.
    let (status, _body) = env
        .ui_post(
            &format!("/ui/requests/{request_id}/approve"),
            &[("csrf_token", "garbage"), ("secret_value", "v")],
        )
        .await
        .unwrap();
    assert_eq!(status, 403);

    // Missing CSRF token → 4xx, never approved.
    let (status, _body) = env
        .ui_post(
            &format!("/ui/requests/{request_id}/deny"),
            &[("csrf_token", "")],
        )
        .await
        .unwrap();
    assert_eq!(status, 403);

    // Valid CSRF token but cross-site Origin → 403.
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    let token = extract_csrf(&page, &format!("/ui/requests/{request_id}/approve")).unwrap();
    let resp = env
        .operator()
        .post(&format!("/ui/requests/{request_id}/approve"))
        .header(reqwest::header::ORIGIN, "https://evil.example")
        .form(&[("csrf_token", token.as_str()), ("secret_value", "v")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // After all that, the request is still pending (nothing acted).
    let state: String = sqlx::query_scalar("SELECT state FROM access_requests WHERE id = $1")
        .bind(request_id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(state, "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn ownership_on_wait_and_no_store_on_read() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("own-1", "owned-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    // Another client's wait on this request → 404 (addendum #1).
    let resp = env
        .fa()
        .get(&format!(
            "/v1/access-requests/{request_id}/wait?timeout_seconds=1"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // Status endpoint likewise.
    let resp = env
        .fa()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Approve and read: the release response is Cache-Control: no-store.
    env.approve(&request_id, &[("secret_value", "no-store-check")])
        .await
        .unwrap();
    let st: serde_json::Value = env
        .k8s()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = st["grant_id"].as_str().unwrap();
    let resp = env
        .k8s()
        .post(&format!("/v1/grants/{grant_id}/read"))
        .json(&serde_json::json!({ "idempotency_key": "ns-1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}
