//! CUJ 3 — agentic autofill (tier 1) with a standing auto-approve policy.

use keychute_e2e::*;

async fn setup(env: &TestEnv) {
    env.seed_secret(
        "hellofresh-login",
        "hunter2",
        "trusted-client",
        "bearer",
        "",
    )
    .await
    .unwrap();
    env.create_policy(&[
        ("client_name", "family-assistant"),
        ("secret_name", "hellofresh-login"),
        ("mechanism", "autofill"),
        ("outcome", "auto-approve"),
        ("priority", "0"),
        ("origins", "hellofresh.com"),
        ("max_ttl_seconds", "86400"),
    ])
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn autofill_auto_approves_and_releases_once_with_replay() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    setup(&env).await;

    // Matching request is approved immediately — no human in the loop.
    let (status, body) = env
        .fa()
        .create_request(autofill_request(
            "af-1",
            "hellofresh-login",
            &["hellofresh.com"],
            3600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["state"], "approved", "auto-approved: {body}");
    let grant_id = body["grant_id"]
        .as_str()
        .expect("grant_id present")
        .to_owned();

    // First read releases the plaintext.
    let (status, body) = env.fa().read_grant(&grant_id, "fill-1").await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["secret"], "hunter2");
    assert_eq!(body["encoding"], "utf8");

    // Same idempotency key within the replay window → identical payload.
    let (status, body2) = env.fa().read_grant(&grant_id, "fill-1").await.unwrap();
    assert_eq!(status, 200, "{body2}");
    assert_eq!(body2["secret"], "hunter2");
    assert_eq!(body2["secret_version_id"], body["secret_version_id"]);

    // A DIFFERENT key is a second logical read: max_uses=1 → 410 exhausted.
    let (status, body3) = env.fa().read_grant(&grant_id, "fill-2").await.unwrap();
    assert_eq!(status, 410, "{body3}");
    assert_eq!(body3["error"]["code"], "grant-exhausted");
}

#[tokio::test(flavor = "multi_thread")]
async fn autofill_off_policy_requests_fall_through_to_pending() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    setup(&env).await;

    // Origin outside the policy → subset rule fails → pending, never auto.
    let (status, body) = env
        .fa()
        .create_request(autofill_request(
            "af-evil",
            "hellofresh-login",
            &["evil.com"],
            3600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["state"], "pending",
        "evil.com must not auto-approve: {body}"
    );
    assert!(body.get("grant_id").is_none());

    // TTL above the policy's max_ttl → pending too.
    let (status, body) = env
        .fa()
        .create_request(autofill_request(
            "af-long",
            "hellofresh-login",
            &["hellofresh.com"],
            999_999,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["state"], "pending",
        "over-TTL must not auto-approve: {body}"
    );
}
