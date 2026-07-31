//! CUJ 1 — brokered HTTP proxy (tier 0): the client never sees the secret.

use keychute_e2e::*;

/// Seed the standard brokered secret + an approved single-origin grant.
/// Returns (request_id, grant_id).
async fn approved_brokered_grant(env: &TestEnv) -> (String, String) {
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();

    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "cuj1-idem",
            "example-api-token",
            "localhost",
            env.upstream_port,
            &["GET", "POST"],
            &["/v1"],
            600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["state"], "pending");
    let request_id = body["request_id"].as_str().unwrap().to_owned();

    env.approve(&request_id, &[]).await.unwrap();

    // Grant id via the status endpoint.
    let resp = env
        .fa()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(st["state"], "approved");
    let grant_id = st["grant_id"].as_str().unwrap().to_owned();
    (request_id, grant_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn brokered_proxy_injects_credential_and_strips_caller_headers() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let (request_id, grant_id) = approved_brokered_grant(&env).await;

    // POST through the proxy carrying everything that must be stripped.
    let resp = env
        .fa()
        .post(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .query(&[("q", "1")])
        .header("Cookie", "session=steal-me")
        .header("X-Forwarded-For", "6.6.6.6")
        .header("X-Forwarded-Host", "evil.example")
        .header("X-HTTP-Method-Override", "DELETE")
        .header("X-Custom-Passthrough", "keep-me")
        .body("hello-upstream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "proxied responses are no-store (addendum #14)"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("\"ok\":true"),
        "upstream body streamed back: {body}"
    );

    let recs = env.upstream_requests.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/v1/echo");
    assert_eq!(r.query.as_deref(), Some("q=1"));
    assert_eq!(r.body, b"hello-upstream");
    // Credential injected; the caller's Keychute bearer never forwarded.
    assert_eq!(r.header("authorization"), Some("Bearer tok-abc"));
    // Host synthesized from the approved origin.
    assert_eq!(
        r.header("host"),
        Some(format!("localhost:{}", env.upstream_port).as_str())
    );
    // Strip list enforced.
    assert_eq!(r.header("cookie"), None);
    assert_eq!(r.header("x-forwarded-for"), None);
    assert_eq!(r.header("x-forwarded-host"), None);
    assert_eq!(r.header("x-http-method-override"), None);
    // Benign custom headers pass through.
    assert_eq!(r.header("x-custom-passthrough"), Some("keep-me"));

    // Audit rows carry method/path/status.
    type AuditRow = (String, Option<String>, Option<String>, Option<i32>);
    let rid: uuid::Uuid = request_id.parse().unwrap();
    // Polled, not read once: the completion row is written by a DETACHED task
    // (server/src/proxy.rs — audit persistence must never delay delivery of the
    // upstream body, or a slow insert would eat the caller's deadline), so it
    // can legitimately land just after the response the client already holds.
    // Reading immediately makes this test race the server for no reason; the
    // invariant being asserted is that the row appears, not when.
    let rows: Vec<AuditRow> = poll_until(
        "proxy-attempt + proxy-completed audit rows",
        std::time::Duration::from_secs(10),
        || async {
            let rows: Vec<AuditRow> = sqlx::query_as(
                "SELECT kind, method, path, status FROM audit_log \
                 WHERE request_id = $1 AND kind IN ('proxy-attempt', 'proxy-completed') \
                 ORDER BY id",
            )
            .bind(rid)
            .fetch_all(&env.db)
            .await
            .ok()?;
            rows.iter()
                .any(|r| r.0 == "proxy-completed")
                .then_some(rows)
        },
    )
    .await;
    let kinds: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert!(kinds.contains(&"proxy-attempt"), "{kinds:?}");
    assert!(kinds.contains(&"proxy-completed"), "{kinds:?}");
    // The write-ahead attempt row also records where the credential was about
    // to be sent (no status yet: it commits before the upstream exchange).
    // The recorded path carries the caller's query string: it is forwarded
    // upstream verbatim and is not constrained by the grant, so omitting it
    // would make `?limit=10` and `?transfer_to=attacker` indistinguishable
    // after the fact.
    let attempt = rows.iter().find(|r| r.0 == "proxy-attempt").unwrap();
    assert_eq!(attempt.1.as_deref(), Some("POST"));
    assert_eq!(attempt.2.as_deref(), Some("/v1/echo?q=1"));
    assert_eq!(attempt.3, None);
    let completed = rows.iter().find(|r| r.0 == "proxy-completed").unwrap();
    assert_eq!(completed.1.as_deref(), Some("POST"));
    assert_eq!(completed.2.as_deref(), Some("/v1/echo?q=1"));
    assert_eq!(completed.3, Some(200));
}

#[tokio::test(flavor = "multi_thread")]
async fn brokered_proxy_never_forwards_trace() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("example-api-token", "tok-abc", "brokered", "bearer", "")
        .await
        .unwrap();
    // Even a grant that explicitly lists TRACE must not proxy it: a
    // TRACE-capable upstream would echo the injected credential header back
    // into the response body.
    let (status, body) = env
        .fa()
        .create_request(brokered_request(
            "cuj1-trace",
            "example-api-token",
            "localhost",
            env.upstream_port,
            &["GET", "TRACE"],
            &["/v1"],
            600,
        ))
        .await
        .unwrap();
    assert_eq!(status, 201, "{body}");
    let request_id = body["request_id"].as_str().unwrap().to_owned();
    env.approve(&request_id, &[]).await.unwrap();
    let resp = env
        .fa()
        .get(&format!("/v1/access-requests/{request_id}"))
        .send()
        .await
        .unwrap();
    let st: serde_json::Value = resp.json().await.unwrap();
    let grant_id = st["grant_id"].as_str().unwrap().to_owned();

    let resp = env
        .fa()
        .request(
            reqwest::Method::TRACE,
            &format!("/v1/grants/{grant_id}/proxy/v1/echo"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "policy-denied");
    // The upstream never saw the request (no credential ever left).
    assert!(env.upstream_requests.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn brokered_proxy_enforces_method_and_path_constraints() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let (_request_id, grant_id) = approved_brokered_grant(&env).await;

    // Method not in the grant → 403.
    let resp = env
        .fa()
        .request(
            reqwest::Method::DELETE,
            &format!("/v1/grants/{grant_id}/proxy/v1/echo"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "policy-denied");

    // Path outside /v1 → 403.
    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v2/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Prefix must match at a segment boundary: /v1x is NOT under /v1.
    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1x/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Literal dot-dot traversal → 400 (raw socket: reqwest normalizes `..`).
    let raw = env
        .raw_http(&format!(
            "GET /v1/grants/{grant_id}/proxy/v1/../secret HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Bearer {FA_TOKEN}\r\n\
             Connection: close\r\n\r\n"
        ))
        .await
        .unwrap();
    assert!(
        raw.starts_with("HTTP/1.1 400"),
        "dot-dot traversal must 400: {raw}"
    );

    // Encoded-slash traversal → 400.
    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1/a%2Fb"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid-path");

    // Encoded dot-dot → 400. Raw socket: WHATWG URL clients (reqwest) resolve
    // `%2e%2e` to `..` and normalize it away before sending.
    let raw = env
        .raw_http(&format!(
            "GET /v1/grants/{grant_id}/proxy/v1/%2e%2e/secret HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Bearer {FA_TOKEN}\r\n\
             Connection: close\r\n\r\n"
        ))
        .await
        .unwrap();
    assert!(
        raw.starts_with("HTTP/1.1 400"),
        "encoded dot-dot must 400: {raw}"
    );

    // None of the rejected calls reached the upstream.
    assert!(
        env.upstream_requests.lock().unwrap().is_empty(),
        "constraint rejections must not touch the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn brokered_proxy_passes_redirects_through_verbatim() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let (_request_id, grant_id) = approved_brokered_grant(&env).await;

    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1/redirect"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "server must not follow redirects");
    assert_eq!(resp.headers().get("location").unwrap(), "/elsewhere");

    // Exactly one upstream request: the redirect target was never fetched.
    let recs = env.upstream_requests.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].path, "/v1/redirect");
}

#[tokio::test(flavor = "multi_thread")]
async fn brokered_grant_is_owner_scoped() {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    let (_request_id, grant_id) = approved_brokered_grant(&env).await;

    // A different authenticated client gets 404, not 403 (addendum #1).
    let resp = env
        .k8s()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(env.upstream_requests.lock().unwrap().is_empty());
}

/// A `basic` secret with no username source is unusable: the proxy fails
/// closed with `bad-credential-encoding` without ever contacting upstream, so
/// — like the 413 body cap — it must not burn a use of a finite-`max_uses`
/// grant. (The username is nulled directly: the UI create path requires one,
/// so only a legacy row can reach this state.)
#[tokio::test(flavor = "multi_thread")]
async fn unusable_basic_credential_does_not_burn_a_grant_use() {
    unusable_basic_credential_case("injection_username = NULL, injection_header = NULL").await;
}

/// Same property for a username that EXISTS but cannot form a header value.
/// This check lives in `InjectionSpec::validate`, which the proxy runs before
/// use-accounting precisely because it needs no plaintext: a CRLF username
/// would split the outbound `Authorization` header, so nothing reaches
/// upstream and no use may be spent. (Rejecting CR/LF/NUL in the decrypted
/// secret itself is unavoidably post-accounting — see `injection_header`.)
#[tokio::test(flavor = "multi_thread")]
async fn header_splitting_basic_username_does_not_burn_a_grant_use() {
    unusable_basic_credential_case(
        "injection_username = 'svc' || chr(13) || chr(10) || 'X-Evil: 1', \
         injection_header = NULL",
    )
    .await;
}

/// Break a seeded `basic` secret's injection template with `break_assignments`,
/// prove the proxy refuses it without contacting upstream or accounting a use,
/// then repair the row and prove the grant's single use is still spendable.
async fn unusable_basic_credential_case(break_assignments: &str) {
    let env = TestEnv::spawn(SpawnOpts::default()).await.unwrap();
    env.seed_secret("basic-api-token", "p4ss", "brokered", "basic", "svc")
        .await
        .unwrap();
    sqlx::query(&format!(
        "UPDATE secrets SET {break_assignments} WHERE name = $1"
    ))
    .bind("basic-api-token")
    .execute(&env.db)
    .await
    .unwrap();

    let mut req = brokered_request(
        "cuj1-basic",
        "basic-api-token",
        "localhost",
        env.upstream_port,
        &["GET"],
        &["/v1"],
        600,
    );
    req["constraints"]["max_uses"] = serde_json::json!(1);
    let (status, body) = env.fa().create_request(req).await.unwrap();
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

    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad-credential-encoding");
    assert!(env.upstream_requests.lock().unwrap().is_empty());
    // Nothing was accounted: no write-ahead attempt row either.
    let rid: uuid::Uuid = request_id.parse().unwrap();
    let kinds = env.audit_kinds_for_request(rid).await;
    assert!(
        !kinds.iter().any(|k| k == "proxy-attempt"),
        "unusable credential must not write an attempt row: {kinds:?}"
    );

    // Repair the row: the single use is still there to spend.
    sqlx::query(
        "UPDATE secrets SET injection_username = $2, injection_header = NULL WHERE name = $1",
    )
    .bind("basic-api-token")
    .bind("svc")
    .execute(&env.db)
    .await
    .unwrap();
    let resp = env
        .fa()
        .get(&format!("/v1/grants/{grant_id}/proxy/v1/echo"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the grant's one use was never burned");
    let recs = env.upstream_requests.lock().unwrap().clone();
    assert_eq!(recs.len(), 1);
    assert_eq!(
        recs[0].header("authorization"),
        Some(format!("Basic {}", base64_std("svc:p4ss")).as_str())
    );
}

fn base64_std(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}
