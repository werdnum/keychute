//! Declarative provisioning (config `secrets:` / `policies:`) plus the
//! `aws-sigv4` injection kind, end to end: a secret and an auto-approve policy
//! provisioned from config let family-assistant make a signed S3-style GET
//! with no human in the loop, and the signature covers exactly the request
//! the upstream received.

use keychute_e2e::*;

const ACCESS_KEY_ID: &str = "lake-media-read";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

async fn provisioned_env() -> TestEnv {
    let mut env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let value_file = env.dir.path().join("minio-secret-key");
    // Trailing newline, as `kubectl create secret --from-file` often leaves.
    std::fs::write(&value_file, format!("{SECRET_KEY}\n")).unwrap();
    env.append_config(&format!(
        "secrets:\n\
         \x20 - name: minio-lake-media\n\
         \x20   description: read-only lake-media\n\
         \x20   injection:\n\
         \x20     kind: aws-sigv4\n\
         \x20     access_key_id: {ACCESS_KEY_ID}\n\
         \x20     region: us-east-1\n\
         \x20     service: s3\n\
         \x20   value_file: {value_file}\n\
         policies:\n\
         \x20 - client: family-assistant\n\
         \x20   secret: minio-lake-media\n\
         \x20   mechanism: brokered\n\
         \x20   outcome: auto-approve\n\
         \x20   origins: [\"localhost:{port}\"]\n\
         \x20   methods: [GET, HEAD]\n\
         \x20   path_prefixes: [/lake-media/sha256]\n\
         \x20   max_ttl_seconds: 600\n",
        value_file = value_file.display(),
        port = env.upstream_port,
    ))
    .unwrap();
    env.restart_server().await.unwrap();
    env
}

#[tokio::test(flavor = "multi_thread")]
async fn provisioned_sigv4_secret_signs_exactly_what_is_sent() {
    let env = provisioned_env().await;

    // Auto-approved by the provisioned policy: no operator action.
    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "sigv4-1",
            "minio-lake-media",
            "localhost",
            env.upstream_port,
            &["GET"],
            &["/lake-media/sha256/ab"],
            300,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["state"], "approved", "{body}");
    let grant_id = body["grant_id"].as_str().unwrap().to_owned();

    let resp = env
        .fa()
        .get(&format!(
            "/v1/grants/{grant_id}/proxy/lake-media/sha256/ab/abc%20def"
        ))
        .query(&[("versionId", "v 1")])
        .header("X-Amz-Meta-Note", "kept and signed")
        .header("X-Amz-Date", "19990101T000000Z")
        .header("X-Amz-Copy-Source", "other-bucket/secret-object")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let recs = env.upstream_requests.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.path, "/lake-media/sha256/ab/abc%20def");
    assert_eq!(
        r.header("x-amz-copy-source"),
        None,
        "a copy source would read outside the grant's path constraint"
    );
    let amz_date = r.header("x-amz-date").unwrap().to_owned();
    assert_ne!(
        amz_date, "19990101T000000Z",
        "the caller's date is replaced"
    );
    let authorization = r.header("authorization").unwrap().to_owned();
    assert!(
        authorization.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={ACCESS_KEY_ID}/{}/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-note, Signature=",
            &amz_date[..8]
        )),
        "{authorization}"
    );
    assert!(
        !authorization.contains(SECRET_KEY),
        "the secret key itself never travels"
    );

    // Recompute from what the upstream actually received: same signature.
    let now = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ")
        .unwrap()
        .and_utc();
    let host = format!("localhost:{}", env.upstream_port);
    let expected = keychute_server::sigv4::sign(
        &keychute_server::sigv4::Scope {
            access_key_id: ACCESS_KEY_ID,
            region: "us-east-1",
            service: "s3",
        },
        SECRET_KEY.as_bytes(),
        &keychute_server::sigv4::Request {
            method: &r.method,
            host: &host,
            wire_path: &r.path,
            query: r.query.as_deref(),
            extra_signed_headers: vec![(
                "x-amz-meta-note".into(),
                r.header("x-amz-meta-note").unwrap().to_owned(),
            )],
            payload: &r.body,
        },
        now,
    );
    assert_eq!(authorization, expected.authorization);
    assert_eq!(
        r.header("x-amz-content-sha256"),
        Some(expected.content_sha256.as_str())
    );
    assert_eq!(r.header("host"), Some(host.as_str()));
}

#[tokio::test(flavor = "multi_thread")]
async fn provisioned_rows_are_read_only_in_the_ui_and_stable_across_restarts() {
    let mut env = provisioned_env().await;

    let page = env.ui_get("/ui/secrets").await.unwrap();
    assert!(page.contains("minio-lake-media") && page.contains("aws-sigv4"));
    assert!(
        !page.contains("/delete\""),
        "no delete form for the managed secret: {page}"
    );

    // Rotating it through the form is refused rather than silently reverted
    // at the next restart.
    let html = env.ui_get("/ui/secrets").await.unwrap();
    let token = extract_csrf(&html, "/ui/secrets").unwrap();
    let (status, body) = env
        .ui_post(
            "/ui/secrets",
            &[
                ("csrf_token", &token),
                ("name", "minio-lake-media"),
                ("secret_value", "operator-typed"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(status, 409, "{body}");

    let policies = env.ui_get("/ui/policies").await.unwrap();
    assert!(
        !policies.contains("/delete\""),
        "no delete form for the managed policy: {policies}"
    );

    // A restart with unchanged config writes no new version and no audit.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&env.db)
        .await
        .unwrap();
    env.restart_server().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&env.db)
        .await
        .unwrap();
    assert_eq!(before, after);
    let version: i32 =
        sqlx::query_scalar("SELECT current_version FROM secrets WHERE name = 'minio-lake-media'")
            .fetch_one(&env.db)
            .await
            .unwrap();
    assert_eq!(version, 1);
}
