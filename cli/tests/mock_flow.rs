//! End-to-end test of the CLI against a local axum mock server:
//! create -> pending, wait -> approved, read -> secret. Asserts exact stdout
//! bytes and that everything else stays on stderr.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use uuid::Uuid;

const REQUEST_ID: &str = "11111111-1111-1111-1111-111111111111";
const GRANT_ID: &str = "22222222-2222-2222-2222-222222222222";
const SECRET_BYTES: &[u8] = b"s3kr\xc3\xa9t-value\n\x00tail";

/// What the mock's grant-read endpoint does.
#[derive(Clone, Copy, PartialEq)]
enum ReadMode {
    /// Release the secret.
    Release,
    /// Answer 410 with this `ApiError` code.
    Gone(&'static str),
    /// Answer 410 with a body that is not an `ApiError` envelope.
    GoneGarbage,
}

#[derive(Clone)]
struct MockConfig {
    deny: bool,
    read_mode: ReadMode,
    /// Fail the first creation attempt with 503 (server committed nothing the
    /// client can see) to exercise the creation retry.
    fail_first_create: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        MockConfig {
            deny: false,
            read_mode: ReadMode::Release,
            fail_first_create: false,
        }
    }
}

#[derive(Clone)]
struct MockState {
    cfg: MockConfig,
    wait_calls: Arc<AtomicUsize>,
    read_calls: Arc<AtomicUsize>,
    /// Every idempotency key the create endpoint saw, in order.
    create_keys: Arc<Mutex<Vec<String>>>,
}

async fn create_request(
    State(st): State<MockState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    assert_eq!(body["secret_name"], "my-service-api-key");
    assert_eq!(body["mechanism"], "cli-read");
    assert_eq!(body["constraints"]["ttl_seconds"], 3600);
    assert_eq!(body["constraints"]["max_uses"], 1);
    assert_eq!(body["context"]["reason"], "seal into ns");
    // Pipeline capture is best-effort; when present it must be a string array.
    if let Some(p) = body["context"]["structured"].get("pipeline") {
        assert!(p.as_array().is_some_and(|a| !a.is_empty()));
    }
    assert_eq!(body["context"]["structured"]["extra"], "extra-context");

    let key = body["idempotency_key"]
        .as_str()
        .expect("idempotency_key must be a string")
        .to_string();
    let attempt = {
        let mut keys = st.create_keys.lock().unwrap();
        keys.push(key);
        keys.len()
    };
    if st.cfg.fail_first_create && attempt == 1 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {"code": "unavailable", "message": "try again"},
            })),
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "pending",
        })),
    )
}

async fn wait_request(
    State(st): State<MockState>,
    Path(id): Path<Uuid>,
) -> Json<serde_json::Value> {
    assert_eq!(id.to_string(), REQUEST_ID);
    let n = st.wait_calls.fetch_add(1, Ordering::SeqCst);
    if n == 0 {
        // First poll: still pending — exercises the polling loop.
        return Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "pending",
        }));
    }
    if st.cfg.deny {
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "denied",
            "deny_reason": "not today",
        }))
    } else {
        Json(serde_json::json!({
            "request_id": REQUEST_ID,
            "state": "approved",
            "grant_id": GRANT_ID,
        }))
    }
}

async fn read_grant(
    State(st): State<MockState>,
    Path(id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, axum::body::Body) {
    assert_eq!(id.to_string(), GRANT_ID);
    // Read idempotency key must be derived from the request key.
    assert_eq!(body["idempotency_key"], "cli-testkey");
    st.read_calls.fetch_add(1, Ordering::SeqCst);
    match st.cfg.read_mode {
        ReadMode::Release => (
            StatusCode::OK,
            axum::body::Body::from(
                serde_json::json!({
                    "secret": base64::engine::general_purpose::STANDARD.encode(SECRET_BYTES),
                    "encoding": "base64",
                    "secret_version_id": "33333333-3333-3333-3333-333333333333",
                })
                .to_string(),
            ),
        ),
        ReadMode::Gone(code) => (
            StatusCode::GONE,
            axum::body::Body::from(
                serde_json::json!({
                    "error": {"code": code, "message": format!("mock says {code}")},
                })
                .to_string(),
            ),
        ),
        ReadMode::GoneGarbage => (StatusCode::GONE, axum::body::Body::from("<html>nope")),
    }
}

async fn start_mock(cfg: MockConfig) -> (String, MockState) {
    let state = MockState {
        cfg,
        wait_calls: Arc::new(AtomicUsize::new(0)),
        read_calls: Arc::new(AtomicUsize::new(0)),
        create_keys: Arc::new(Mutex::new(Vec::new())),
    };
    let app = Router::new()
        .route("/v1/access-requests", post(create_request))
        .route("/v1/access-requests/{id}/wait", get(wait_request))
        .route("/v1/grants/{id}/read", post(read_grant))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

fn run_cli(url: &str) -> std::process::Output {
    let url = url.to_string();
    Command::new(env!("CARGO_BIN_EXE_keychute"))
        .args([
            "request",
            "my-service-api-key",
            "--reason",
            "seal into ns",
            "--idempotency-key",
            "testkey",
            "--timeout",
            "30",
        ])
        .env("KEYCHUTE_URL", &url)
        .env("KEYCHUTE_TOKEN", "test-token")
        .env("KEYCHUTE_CONTEXT", "extra-context")
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .env_remove("KEYCHUTE_CA_BUNDLE")
        .env_remove("KEYCHUTE_EXTERNAL_URL")
        .output()
        .expect("failed to run keychute binary")
}

async fn run_against(cfg: MockConfig) -> (std::process::Output, MockState) {
    let (url, state) = start_mock(cfg).await;
    let out = tokio::task::spawn_blocking(move || run_cli(&url))
        .await
        .unwrap();
    (out, state)
}

#[tokio::test]
async fn pending_then_approved_prints_exact_secret_bytes() {
    let (out, state) = run_against(MockConfig::default()).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected success, got {:?}; stderr: {stderr}",
        out.status
    );
    // Exact raw bytes, no trailing newline added (stdout is a pipe, not a TTY).
    assert_eq!(out.stdout, SECRET_BYTES, "stdout must be the raw secret");
    // The approval hint goes to stderr, and the secret never does.
    assert!(stderr.contains("Waiting for approval"), "{stderr}");
    assert!(
        stderr.contains(&format!("/ui/requests/{REQUEST_ID}")),
        "{stderr}"
    );
    assert!(!out.stderr.windows(5).any(|w| w == b"s3kr\xc3"));
    assert!(state.wait_calls.load(Ordering::SeqCst) >= 2);
    assert_eq!(state.read_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.create_keys.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn denied_request_exits_3_with_no_stdout() {
    let (out, _state) = run_against(MockConfig {
        deny: true,
        ..MockConfig::default()
    })
    .await;
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "{stderr}");
    assert!(stderr.contains("not today"), "{stderr}");
}

/// The server returns 410 for three different conditions; each maps to its own
/// exit code so callers can tell "re-request" from "already used".
async fn assert_gone_maps_to(mode: ReadMode, want_code: i32, want_stderr: &str) {
    let (out, state) = run_against(MockConfig {
        read_mode: mode,
        ..MockConfig::default()
    })
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(want_code), "stderr: {stderr}");
    assert!(out.stdout.is_empty(), "410 must not print anything");
    assert!(stderr.contains(want_stderr), "{stderr}");
    // A definitive 410 must not be retried.
    assert_eq!(state.read_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gone_payload_lost_exits_5() {
    assert_gone_maps_to(ReadMode::Gone("payload-lost"), 5, "payload was lost").await;
}

#[tokio::test]
async fn gone_grant_expired_exits_4() {
    assert_gone_maps_to(ReadMode::Gone("grant-expired"), 4, "has expired").await;
}

#[tokio::test]
async fn gone_grant_exhausted_exits_1() {
    assert_gone_maps_to(ReadMode::Gone("grant-exhausted"), 1, "no uses remaining").await;
}

#[tokio::test]
async fn gone_unparseable_body_exits_1() {
    assert_gone_maps_to(ReadMode::GoneGarbage, 1, "no longer usable").await;
}

#[tokio::test]
async fn creation_retries_reuse_the_same_idempotency_key() {
    let (out, state) = run_against(MockConfig {
        fail_first_create: true,
        ..MockConfig::default()
    })
    .await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected success, got {:?}; stderr: {stderr}",
        out.status
    );
    assert_eq!(out.stdout, SECRET_BYTES);
    let keys = state.create_keys.lock().unwrap().clone();
    assert_eq!(keys.len(), 2, "creation should be retried exactly once");
    // Same key on the retry: the server replays the original request instead of
    // creating a duplicate pending request (and a duplicate operator push).
    assert_eq!(keys[0], keys[1]);
    assert_eq!(keys[0], "testkey");
    assert!(
        stderr.contains("request creation attempt 1/3 failed"),
        "{stderr}"
    );
}
