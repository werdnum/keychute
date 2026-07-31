//! End-to-end test of `keychute curl` against a local axum mock: create a
//! brokered request -> pending -> approved -> proxy. Asserts the constraints
//! the CLI derives from the URL, the request it actually proxies, and that the
//! upstream's bytes reach stdout unmodified while everything else is stderr.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use uuid::Uuid;

const REQUEST_ID: &str = "11111111-1111-1111-1111-111111111111";
const GRANT_ID: &str = "22222222-2222-2222-2222-222222222222";
/// Not valid UTF-8 and with no trailing newline: the body must arrive byte for
/// byte, not round-tripped through a string or "helpfully" terminated.
const UPSTREAM_BODY: &[u8] = b"{\"ok\":true,\"b\":\"\xff\xfe\"}";

/// What the mock's proxy endpoint answers with.
#[derive(Clone, Copy, PartialEq)]
enum ProxyMode {
    /// Stream the upstream body back.
    Upstream,
    /// Keychute's OWN refusal: an error envelope WITH the marker header.
    KeychuteError(StatusCode, &'static str),
    /// An upstream error response — same status, same envelope shape, but no
    /// marker header. Must NOT be read as a Keychute refusal.
    UpstreamError(StatusCode),
}

/// One proxied request, as the mock saw it.
#[derive(Clone, Debug)]
struct ProxyRecord {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ProxyRecord {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone)]
struct MockState {
    mode: ProxyMode,
    /// Origin the mock's grant is approved for.
    grant_host: &'static str,
    wait_calls: Arc<AtomicUsize>,
    create_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
    proxied: Arc<Mutex<Vec<ProxyRecord>>>,
}

async fn create_request(
    State(st): State<MockState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    st.create_bodies.lock().unwrap().push(body);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"request_id": REQUEST_ID, "state": "pending"})),
    )
}

async fn wait_request(
    State(st): State<MockState>,
    Path(id): Path<Uuid>,
) -> Json<serde_json::Value> {
    assert_eq!(id.to_string(), REQUEST_ID);
    if st.wait_calls.fetch_add(1, Ordering::SeqCst) == 0 {
        // Still pending on the first poll: exercises the polling loop.
        return Json(serde_json::json!({"request_id": REQUEST_ID, "state": "pending"}));
    }
    Json(serde_json::json!({
        "request_id": REQUEST_ID,
        "state": "approved",
        "grant_id": GRANT_ID,
    }))
}

/// GET /v1/grants/{id} — the metadata the CLI checks a reused grant against.
async fn grant_info(State(st): State<MockState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    assert_eq!(id.to_string(), GRANT_ID);
    Json(serde_json::json!({
        "grant_id": GRANT_ID,
        "mechanism": "brokered",
        "constraints": {
            "origins": [{"host": st.grant_host}],
            "methods": ["GET", "POST"],
            "path_prefixes": ["/v1"],
            "ttl_seconds": 300,
            "max_uses": 5,
        },
        "not_after": "2099-01-01T00:00:00Z",
        "max_uses": 5,
        "use_count": 1,
        "revoked": false,
    }))
}

async fn proxy(State(st): State<MockState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let raw = parts.uri.path().to_string();
    let suffix = raw
        .strip_prefix(&format!("/v1/grants/{GRANT_ID}/proxy"))
        .expect("proxy prefix")
        .to_string();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap().to_vec();
    st.proxied.lock().unwrap().push(ProxyRecord {
        method: parts.method.to_string(),
        path: suffix,
        query: parts.uri.query().map(|q| q.to_string()),
        headers,
        body,
    });

    match st.mode {
        ProxyMode::Upstream => (
            StatusCode::OK,
            [("content-type", "application/json"), ("x-upstream", "yes")],
            Bytes::from_static(UPSTREAM_BODY),
        )
            .into_response(),
        ProxyMode::KeychuteError(status, code) => {
            let mut resp = (
                status,
                Json(serde_json::json!({"error": {"code": code, "message": "nope"}})),
            )
                .into_response();
            resp.headers_mut()
                .insert("x-keychute-error", code.parse().unwrap());
            resp
        }
        ProxyMode::UpstreamError(status) => (
            status,
            // Deliberately the same envelope shape a Keychute error uses: the
            // marker header, not the body, is what tells them apart.
            Json(serde_json::json!({"error": {"code": "policy-denied", "message": "upstream"}})),
        )
            .into_response(),
    }
}

async fn spawn_mock(mode: ProxyMode) -> (String, MockState) {
    spawn_mock_for(mode, "api.example.com").await
}

async fn spawn_mock_for(mode: ProxyMode, grant_host: &'static str) -> (String, MockState) {
    let st = MockState {
        mode,
        grant_host,
        wait_calls: Arc::new(AtomicUsize::new(0)),
        create_bodies: Arc::new(Mutex::new(Vec::new())),
        proxied: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/v1/access-requests", post(create_request))
        .route("/v1/access-requests/{id}/wait", get(wait_request))
        .route("/v1/grants/{id}", get(grant_info))
        .route("/v1/grants/{id}/proxy", any(proxy))
        .route("/v1/grants/{id}/proxy/{*rest}", any(proxy))
        .with_state(st.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), st)
}

fn cli_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("keychute")
}

fn run_cli(base: &str, args: &[&str]) -> (i32, Vec<u8>, String) {
    let out = Command::new(cli_bin())
        .args(args)
        .env("KEYCHUTE_URL", base)
        .env("KEYCHUTE_TOKEN", "client-token")
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .env_remove("KEYCHUTE_CONTEXT")
        .output()
        .expect("running keychute CLI");
    (
        out.status.code().unwrap_or(-1),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn curl_requests_a_narrow_grant_and_streams_the_upstream_response() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;

    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/things?limit=10",
                "--secret",
                "example-api-token",
                "-X",
                "post",
                "-H",
                "Content-Type: application/json",
                "-H",
                "Authorization: Bearer mine",
                "-d",
                "{\"a\":1}",
                "--reason",
                "list the things",
                "--timeout",
                "30",
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "cli failed: {stderr}");

    // The upstream's bytes, verbatim: no re-encoding, no added newline.
    assert_eq!(stdout, UPSTREAM_BODY);

    // The grant asked for covers exactly this call.
    let created = st.create_bodies.lock().unwrap().clone();
    assert_eq!(created.len(), 1);
    let c = &created[0];
    assert_eq!(c["secret_name"], "example-api-token");
    assert_eq!(c["mechanism"], "brokered");
    assert_eq!(c["constraints"]["origins"][0]["host"], "api.example.com");
    assert!(
        c["constraints"]["origins"][0]["port"].is_null(),
        "default 443 stays implicit: {c}"
    );
    assert_eq!(c["constraints"]["methods"], serde_json::json!(["POST"]));
    assert_eq!(
        c["constraints"]["path_prefixes"],
        serde_json::json!(["/v1/things"]),
        "the path, not the host"
    );
    assert_eq!(c["constraints"]["max_uses"], 1);
    assert_eq!(c["context"]["reason"], "list the things");
    // The operator reads the full target, query string included — it is
    // forwarded verbatim and the grant does not constrain it.
    assert_eq!(
        c["context"]["structured"]["target"],
        "POST https://api.example.com/v1/things?limit=10"
    );

    // What went through the proxy.
    let proxied = st.proxied.lock().unwrap().clone();
    assert_eq!(proxied.len(), 1);
    let p = &proxied[0];
    assert_eq!(p.method, "POST");
    assert_eq!(p.path, "/v1/things");
    assert_eq!(p.query.as_deref(), Some("limit=10"));
    assert_eq!(p.body, b"{\"a\":1}");
    assert_eq!(p.header("content-type"), Some("application/json"));
    // The client's own Keychute credential authenticates the proxy hop...
    assert_eq!(p.header("authorization"), Some("Bearer client-token"));
    // ...which is why a caller-supplied Authorization is dropped locally, with
    // a warning, instead of silently colliding with it.
    assert!(
        stderr.contains("not forwarded by the broker"),
        "stripped-header warning: {stderr}"
    );
    // Diagnostics stay on stderr so stdout is pipeable.
    assert!(stderr.contains("200 OK"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn curl_reuses_a_grant_without_a_second_approval() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;

    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/things/42",
                "--grant-id",
                GRANT_ID,
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "cli failed: {stderr}");
    assert_eq!(stdout, UPSTREAM_BODY);
    // No access request, no push, no human: the grant was already approved.
    assert!(st.create_bodies.lock().unwrap().is_empty());
    let proxied = st.proxied.lock().unwrap().clone();
    assert_eq!(proxied[0].method, "GET");
    assert_eq!(proxied[0].path, "/v1/things/42");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keychute_refusal_exits_denied() {
    let (base, _st) = spawn_mock(ProxyMode::KeychuteError(
        StatusCode::FORBIDDEN,
        "policy-denied",
    ))
    .await;

    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/x",
                "--grant-id",
                GRANT_ID,
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 3, "denied exit code: {stderr}");
    assert!(stdout.is_empty(), "no body on a refusal");
    assert!(stderr.contains("policy-denied"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_403_is_data_not_a_denial() {
    // Same status and body shape as the refusal above, minus the marker
    // header. Treating it as a denial would report "the human said no" about
    // a human who was never asked.
    let (base, _st) = spawn_mock(ProxyMode::UpstreamError(StatusCode::FORBIDDEN)).await;

    let base2 = base.clone();
    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base2,
            &[
                "curl",
                "https://api.example.com/v1/x",
                "--grant-id",
                GRANT_ID,
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "upstream errors are successful calls: {stderr}");
    assert!(
        String::from_utf8_lossy(&stdout).contains("upstream"),
        "the upstream's error document reaches stdout"
    );

    // ...unless --fail is asked for, which is curl's own opt-in.
    let (code, stdout, _stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/x",
                "--grant-id",
                GRANT_ID,
                "--fail",
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "--fail suppresses the body");
}

#[tokio::test(flavor = "multi_thread")]
async fn include_prepends_the_response_head() {
    let (base, _st) = spawn_mock(ProxyMode::Upstream).await;
    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/x",
                "--grant-id",
                GRANT_ID,
                "-i",
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "{stderr}");
    let out = String::from_utf8_lossy(&stdout);
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(out.contains("x-upstream: yes"), "{out}");
    assert!(out.contains("\r\n\r\n{\"ok\":true"), "head/body separator");
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_and_misleading_urls_never_reach_the_server() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;
    for url in [
        "http://api.example.com/v1/x",
        "https://api.example.com@attacker.example/v1/x",
        "ftp://api.example.com/x",
    ] {
        let base = base.clone();
        let arg = url.to_string();
        let (code, _stdout, stderr) =
            tokio::task::spawn_blocking(move || run_cli(&base, &["curl", &arg, "--secret", "s"]))
                .await
                .unwrap();
        assert_eq!(code, 2, "usage error for {url}: {stderr}");
    }
    // Nothing was requested, so no approval was spent finding out.
    assert!(st.create_bodies.lock().unwrap().is_empty());
    assert!(st.proxied.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_target_without_a_secret_or_grant_is_a_usage_error() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;
    let (code, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(&base, &["curl", "https://api.example.com/v1/x"])
    })
    .await
    .unwrap();
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("--secret"), "{stderr}");
    assert!(st.create_bodies.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn reusing_a_grant_against_a_different_origin_is_refused() {
    // The proxy takes the upstream origin from the GRANT, so this call would
    // have been delivered to api.example.com while every diagnostic said
    // other.example. For a POST that is a side effect on the wrong service.
    let (base, st) = spawn_mock_for(ProxyMode::Upstream, "api.example.com").await;
    let (code, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://other.example/v1/things",
                "-X",
                "POST",
                "--grant-id",
                GRANT_ID,
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 2, "usage error: {stderr}");
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("api.example.com"),
        "names the approved origin: {stderr}"
    );
    assert!(
        stderr.contains("other.example"),
        "names the requested origin: {stderr}"
    );
    // Nothing was sent, so nothing was done to either service.
    assert!(st.proxied.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn reusing_a_grant_that_does_not_cover_the_path_is_refused_locally() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;
    let (code, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                // The grant covers /v1; this is a sibling that merely shares a
                // textual prefix.
                "https://api.example.com/v1-admin/things",
                "--grant-id",
                GRANT_ID,
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 2, "{stderr}");
    assert!(st.proxied.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unwritable_output_path_fails_before_the_request_is_sent() {
    let (base, st) = spawn_mock(ProxyMode::Upstream).await;
    let (code, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_cli(
            &base,
            &[
                "curl",
                "https://api.example.com/v1/things",
                "--grant-id",
                GRANT_ID,
                "-o",
                "/nonexistent-dir/keychute-out.json",
            ],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("--output"), "{stderr}");
    // The point of the ordering: a side-effecting call must not have committed
    // upstream before a purely local failure is reported.
    assert!(
        st.proxied.lock().unwrap().is_empty(),
        "nothing may be sent when the destination cannot be opened"
    );
}
