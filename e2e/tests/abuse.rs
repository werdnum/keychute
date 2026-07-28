//! Abuse guards: pending cap, concurrent-wait cap, proxy body cap.

use keychute_e2e::*;

#[tokio::test(flavor = "multi_thread")]
async fn pending_cap_returns_429() {
    let opts = SpawnOpts {
        max_pending_per_client: 2,
        ..SpawnOpts::default()
    };
    let env = TestEnv::spawn(opts).await.unwrap();

    for i in 0..2 {
        let (status, body) = env
            .k8s()
            .create_request(cli_read_request(&format!("cap-{i}"), "cap-secret", 600, ""))
            .await
            .unwrap();
        assert_eq!(status, 201, "pending #{i}: {body}");
    }
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("cap-2", "cap-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"]["code"], "too-many-pending");

    // Another client is unaffected (per-client cap).
    let (status, body) = env
        .fa()
        .create_request(autofill_request("fa-cap", "cap-secret", &["site.com"], 600))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_wait_cap_returns_429() {
    let opts = SpawnOpts {
        max_waits_per_client: 1,
        ..SpawnOpts::default()
    };
    let env = TestEnv::spawn(opts).await.unwrap();

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("wait-cap", "wait-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    // First wait occupies the single slot.
    let first = env
        .k8s()
        .get(&format!(
            "/v1/access-requests/{request_id}/wait?timeout_seconds=6"
        ))
        .send();
    let holder = tokio::spawn(first);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Second concurrent wait → 429.
    let resp = env
        .k8s()
        .get(&format!(
            "/v1/access-requests/{request_id}/wait?timeout_seconds=1"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "too-many-waits");

    // The first wait completes normally (still pending) and frees the slot.
    let resp = holder.await.unwrap().unwrap();
    assert_eq!(resp.status(), 200);
    let resp = env
        .k8s()
        .get(&format!(
            "/v1/access-requests/{request_id}/wait?timeout_seconds=1"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "slot released after the first wait ended"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_body_cap_returns_413() {
    let opts = SpawnOpts {
        proxy_max_body_bytes: 1024,
        ..SpawnOpts::default()
    };
    let env = TestEnv::spawn(opts).await.unwrap();

    env.seed_secret("body-cap-token", "tok-cap", "brokered", "bearer", "")
        .await
        .unwrap();
    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "body-cap",
            "body-cap-token",
            "localhost",
            env.upstream_port,
            &["POST"],
            &["/v1"],
            600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[]).await.unwrap();
    let st: serde_json::Value = env
        .fa()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = st["grant_id"].as_str().unwrap().to_owned();

    // 2 KiB body over a 1 KiB cap → 413, and the upstream never sees it.
    let resp = env
        .fa()
        .post(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .body(vec![b'x'; 2048])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "body-too-large");
    assert!(env.upstream_requests.lock().unwrap().is_empty());

    // A small body still goes through.
    let resp = env
        .fa()
        .post(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .body("small")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
