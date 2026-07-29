//! Crypto lifecycle: ciphertext-only at rest, fail-closed passthrough across
//! restarts, KEK rotation.

use keychute_e2e::*;

const CANARY: &str = "super-secret-payload-xyz";

/// Assert `value` appears nowhere in the sensitive tables — neither as raw
/// bytes in the payload columns nor as text/hex in a full-row textual dump.
async fn assert_absent_from_db(env: &TestEnv, value: &str) {
    let needle = value.as_bytes();
    let hex_needle = hex::encode(needle);
    fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    // Byte-level scan of the payload columns.
    let versions: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT ciphertext, nonce, wrapped_dek FROM secret_versions")
            .fetch_all(&env.db)
            .await
            .unwrap();
    for (ct, nonce, dek) in &versions {
        for col in [ct, nonce, dek] {
            assert!(
                !contains_sub(col, needle),
                "plaintext bytes found in secret_versions"
            );
        }
    }
    let grants: Vec<(Option<Vec<u8>>,)> =
        sqlx::query_as("SELECT passthrough_ciphertext FROM grants")
            .fetch_all(&env.db)
            .await
            .unwrap();
    for (ct,) in grants.iter().flat_map(|(c,)| c.as_ref().map(|c| (c,))) {
        assert!(
            !contains_sub(ct, needle),
            "plaintext bytes found in grants.passthrough_ciphertext"
        );
    }

    // Full-row textual dump (bytea renders as \x<hex>): neither the literal
    // value nor its hex encoding may appear anywhere.
    for table in [
        "secrets",
        "secret_versions",
        "access_requests",
        "grants",
        // The schema comment forbids secret material and freeform client
        // context in audit detail; scan it so a debuggability change that
        // starts writing either into audit_log.detail fails THIS test.
        "audit_log",
        "grant_reads",
    ] {
        let rows: Vec<(String,)> = sqlx::query_as(&format!("SELECT t::text FROM {table} t"))
            .fetch_all(&env.db)
            .await
            .unwrap();
        for (row,) in &rows {
            assert!(
                !row.contains(value),
                "literal plaintext in {table} row: {row}"
            );
            assert!(
                !row.to_ascii_lowercase().contains(&hex_needle),
                "hex-encoded plaintext in {table} row"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_never_at_rest_or_in_logs() {
    let mut env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // Stored secret path.
    env.seed_secret("abc", CANARY, "cooperating-client", "bearer", "")
        .await
        .unwrap();

    // Passthrough path + client context path (reason also mentions the value —
    // context is encrypted at rest).
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request(
            "canary-1",
            "another-secret",
            600,
            &format!("reason mentioning {CANARY}"),
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[("secret_value", CANARY)])
        .await
        .unwrap();

    assert_absent_from_db(&env, CANARY).await;

    // Server logs must never contain the value either. Stop first so the log
    // files are complete.
    env.stop_server();
    let logs = env.server_logs();
    assert!(!logs.is_empty(), "captured server logs");
    assert!(
        !logs.contains(CANARY),
        "secret value leaked into server logs"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_loses_passthrough_and_fails_closed() {
    let mut env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // Approve a passthrough grant but do NOT read it.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("restart-1", "ephemeral-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[("secret_value", "lost-on-restart")])
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

    // Restart: the ephemeral process KEK is gone.
    env.restart_server().await.unwrap();

    let (status, body) = env
        .k8s()
        .read_grant(&grant_id, "after-restart")
        .await
        .unwrap();
    assert_eq!(status, 410, "{body}");
    assert_eq!(body["error"]["code"], "payload-lost");

    // A fresh request works end-to-end after the restart.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("restart-2", "ephemeral-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[("secret_value", "fresh-after-restart")])
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
    let (status, body) = env.k8s().read_grant(&grant_id, "fresh-read").await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["secret"], "fresh-after-restart");
}

#[tokio::test(flavor = "multi_thread")]
async fn kek_rotation_keeps_old_secrets_readable() {
    let mut env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();

    // A secret sealed under k1.
    env.seed_secret(
        "old-secret",
        "old-value",
        "cooperating-client",
        "bearer",
        "",
    )
    .await
    .unwrap();
    let kek: String =
        sqlx::query_scalar("SELECT kek_id FROM secret_versions ORDER BY created_at LIMIT 1")
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(kek, "k1");

    // Rotate: k2 becomes active, k1 stays available for opens.
    env.stop_server();
    let k1 = env.k1.clone();
    let mac = env.mac_key.clone();
    let k2 = {
        use base64::Engine;
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        base64::engine::general_purpose::STANDARD.encode(k)
    };
    write_keyset(&env.keyset_path, "k2", &[("k1", &k1), ("k2", &k2)], &mac);
    env.start_server().await.unwrap();

    // Old secret still readable through a freshly approved request.
    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("rot-old", "old-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
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
    let (status, body) = env
        .k8s()
        .read_grant(&grant_id, "rot-old-read")
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["secret"], "old-value");

    // A new secret seals under k2 and reads back too.
    env.seed_secret(
        "new-secret",
        "new-value",
        "cooperating-client",
        "bearer",
        "",
    )
    .await
    .unwrap();
    let kek: String = sqlx::query_scalar(
        "SELECT sv.kek_id FROM secret_versions sv \
         JOIN secrets s ON s.id = sv.secret_id WHERE s.name = 'new-secret'",
    )
    .fetch_one(&env.db)
    .await
    .unwrap();
    assert_eq!(kek, "k2");

    let (status, body) = env
        .k8s()
        .create_request(cli_read_request("rot-new", "new-secret", 600, ""))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
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
    let (status, body) = env
        .k8s()
        .read_grant(&grant_id, "rot-new-read")
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["secret"], "new-value");
}
