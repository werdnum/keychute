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
    let action = format!("/ui/requests/{request_id}/approve");
    let token = extract_csrf(&page, &action).expect("approve form present before expiry");
    // The token is bound to the render-time secret-state marker, so a browser's
    // submission carries both from the same render.
    let present = extract_form_field(&page, &action, "secret_present").expect("state marker");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let (status, _body) = env
        .ui_post(
            &action,
            &[
                ("csrf_token", &token),
                ("secret_present", &present),
                ("secret_value", "too-late"),
            ],
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

/// A grant approved by a human under a standing policy row must expire no
/// later than that row does (DESIGN §5) — approving minutes before a policy
/// lapses must not mint a grant that outlives it. The auto-approve path always
/// applied this cap; the manual-approval path used to discard it.
#[tokio::test(flavor = "multi_thread")]
async fn manual_approval_is_capped_at_standing_policy_expiry() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // A require-approval policy that lapses ~5 minutes from now.
    let policy_not_after = chrono::Utc::now() + chrono::Duration::minutes(5);
    env.create_policy(&[
        ("client_name", "k8s-agent"),
        ("secret_name", "capped-secret"),
        ("mechanism", "cli-read"),
        ("outcome", "require-approval"),
        ("priority", "0"),
        ("max_ttl_seconds", "86400"),
        (
            "not_after",
            &policy_not_after.format("%Y-%m-%dT%H:%M:%S").to_string(),
        ),
    ])
    .await
    .unwrap();

    // Request a TTL far beyond the policy's remaining life.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("cap-1", "capped-secret", 86400, "capped"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["state"], "pending", "policy requires human approval");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    // The operator approves, accepting the full requested TTL.
    env.approve(&request_id, &[("secret_value", "capped-value")])
        .await
        .unwrap();

    let grant_not_after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT g.not_after FROM grants g WHERE g.request_id = $1")
            .bind(request_id.parse::<uuid::Uuid>().unwrap())
            .fetch_one(&env.db)
            .await
            .unwrap();

    assert!(
        grant_not_after <= policy_not_after + chrono::Duration::seconds(1),
        "grant outlives its standing policy: grant {grant_not_after}, policy {policy_not_after}"
    );
}

/// A stale approval form must not silently change meaning. The page renders a
/// value field (and the "released once, to this grant only" promise) only while
/// the secret is absent; if one is created before the form is submitted, the
/// operator's typed credential would otherwise be dropped and the newly stored
/// credential released in its place. That must be a 409 showing the new state.
#[tokio::test(flavor = "multi_thread")]
async fn stale_approval_form_is_refused_when_the_secret_appears_underneath() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("stale-1", "payroll", 600, "pay people"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    let action = format!("/ui/requests/{request_id}/approve");

    // The operator opens the approval page while "payroll" is not stored.
    let page = env
        .ui_get(&format!("/ui/requests/{request_id}"))
        .await
        .unwrap();
    assert!(page.contains("NOT stored in Keychute"));
    let token = extract_csrf(&page, &action).expect("approve csrf token");
    let present = extract_form_field(&page, &action, "secret_present").expect("state marker");
    assert_eq!(present, "0", "page rendered against an absent secret");

    // Someone else stores "payroll" in the meantime.
    env.seed_secret(
        "payroll",
        "stored-credential-A",
        "cooperating-client",
        "bearer",
        "",
    )
    .await
    .unwrap();

    // Submitting the now-stale form (store unticked) must not approve.
    let (status, body) = env
        .ui_post(
            &action,
            &[
                ("csrf_token", &token),
                ("secret_present", &present),
                ("secret_value", "operator-typed-B"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status, 409, "stale approval form must conflict: {body}");
    assert!(
        body.contains("changed while you were reviewing"),
        "409 explains the change: {body}"
    );
    // The 409 body IS the approval page in its new state, ready to re-decide.
    assert!(body.contains("stored, version 1"), "re-rendered: {body}");
    assert!(!body.contains("NOT stored in Keychute"));
    assert!(extract_csrf(&body, &action).is_some(), "fresh csrf token");

    // Nothing was approved: the request is still pending, with no grant.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM grants WHERE request_id = $1")
        .bind(request_id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "stale form must not mint a grant");
    let state: String = sqlx::query_scalar("SELECT state FROM access_requests WHERE id = $1")
        .bind(request_id.parse::<uuid::Uuid>().unwrap())
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(state, "pending");

    // Re-deciding against the fresh page works and releases the stored value —
    // this time knowingly.
    env.approve(&request_id, &[]).await.unwrap();
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
    let (status, body) = env.k8s().read_grant(&grant_id, "stale-read").await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["secret"], "stored-credential-A");
}

/// The render-time marker is authenticated: it is folded into the approve
/// token's MAC, so a token minted against one secret-state does not validate
/// when submitted with the other marker value. Without that binding the marker
/// was advisory — flippable independently of the token — and a doctored form
/// could quietly re-acquire the meaning the operator never saw.
#[tokio::test(flavor = "multi_thread")]
async fn approve_token_is_bound_to_the_rendered_secret_state() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // (1) Page rendered against an ABSENT secret: token is bound to "0".
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("bind-1", "unstored", 600, "why"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let absent_id = body["request_id"].as_str().unwrap().to_owned();
    let absent_action = format!("/ui/requests/{absent_id}/approve");
    let page = env
        .ui_get(&format!("/ui/requests/{absent_id}"))
        .await
        .unwrap();
    let absent_token = extract_csrf(&page, &absent_action).expect("approve csrf token");
    assert_eq!(
        extract_form_field(&page, &absent_action, "secret_present").as_deref(),
        Some("0")
    );

    // Claiming "1" with that token is rejected before any state is consulted.
    let (status, body) = env
        .ui_post(
            &absent_action,
            &[("csrf_token", &absent_token), ("secret_present", "1")],
        )
        .await
        .unwrap();
    assert_eq!(
        status, 403,
        "swapped marker must fail the token check: {body}"
    );
    assert!(body.contains("invalid or expired form token"), "{body}");

    // (2) Page rendered against a STORED secret: token is bound to "1".
    env.seed_secret("bound", "stored-value", "cooperating-client", "bearer", "")
        .await
        .unwrap();
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("bind-2", "bound", 600, "why"))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let stored_id = body["request_id"].as_str().unwrap().to_owned();
    let stored_action = format!("/ui/requests/{stored_id}/approve");
    let page = env
        .ui_get(&format!("/ui/requests/{stored_id}"))
        .await
        .unwrap();
    let stored_token = extract_csrf(&page, &stored_action).expect("approve csrf token");
    assert_eq!(
        extract_form_field(&page, &stored_action, "secret_present").as_deref(),
        Some("1")
    );

    // Downgrading the marker to "0" (which would open the operator-supplied
    // value branch) is rejected the same way.
    let (status, body) = env
        .ui_post(
            &stored_action,
            &[
                ("csrf_token", &stored_token),
                ("secret_present", "0"),
                ("secret_value", "attacker-supplied"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        status, 403,
        "swapped marker must fail the token check: {body}"
    );

    // Dropping the marker entirely breaks the same binding: the token was
    // minted over "1" and no longer verifies without it.
    let (status, body) = env
        .ui_post(&stored_action, &[("csrf_token", &stored_token)])
        .await
        .unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("invalid or expired form token"), "{body}");

    // Neither request was approved.
    for id in [&absent_id, &stored_id] {
        let state: String = sqlx::query_scalar("SELECT state FROM access_requests WHERE id = $1")
            .bind(id.parse::<uuid::Uuid>().unwrap())
            .fetch_one(&env.db)
            .await
            .unwrap();
        assert_eq!(state, "pending", "request {id} must not have been approved");
    }

    // The honest submissions still work.
    env.approve(&stored_id, &[]).await.unwrap();
}
