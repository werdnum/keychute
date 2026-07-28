//! End-to-end test of the CLI against a local axum mock server:
//! create -> pending, wait -> approved, read -> secret. Asserts exact stdout
//! bytes and that everything else stays on stderr.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use uuid::Uuid;

const REQUEST_ID: &str = "11111111-1111-1111-1111-111111111111";
const GRANT_ID: &str = "22222222-2222-2222-2222-222222222222";
const SECRET_BYTES: &[u8] = b"s3kr\xc3\xa9t-value\n\x00tail";

#[derive(Clone)]
struct MockState {
    wait_calls: Arc<AtomicUsize>,
    read_calls: Arc<AtomicUsize>,
    deny: bool,
}

async fn create_request(
    State(_st): State<MockState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    assert_eq!(body["secret_name"], "my-service-api-key");
    assert_eq!(body["mechanism"], "cli-read");
    assert_eq!(body["idempotency_key"], "testkey");
    assert_eq!(body["constraints"]["ttl_seconds"], 3600);
    assert_eq!(body["constraints"]["max_uses"], 1);
    assert_eq!(body["context"]["reason"], "seal into ns");
    // Pipeline capture is best-effort; when present it must be a string array.
    if let Some(p) = body["context"]["structured"].get("pipeline") {
        assert!(p.as_array().is_some_and(|a| !a.is_empty()));
    }
    assert_eq!(body["context"]["structured"]["extra"], "extra-context");
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
    if st.deny {
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
) -> Json<serde_json::Value> {
    assert_eq!(id.to_string(), GRANT_ID);
    // Read idempotency key must be derived from the request key.
    assert_eq!(body["idempotency_key"], "cli-testkey");
    st.read_calls.fetch_add(1, Ordering::SeqCst);
    Json(serde_json::json!({
        "secret": base64::engine::general_purpose::STANDARD.encode(SECRET_BYTES),
        "encoding": "base64",
        "secret_version_id": "33333333-3333-3333-3333-333333333333",
    }))
}

async fn start_mock(deny: bool) -> (String, MockState) {
    let state = MockState {
        wait_calls: Arc::new(AtomicUsize::new(0)),
        read_calls: Arc::new(AtomicUsize::new(0)),
        deny,
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

#[tokio::test]
async fn pending_then_approved_prints_exact_secret_bytes() {
    let (url, state) = start_mock(false).await;
    let out = tokio::task::spawn_blocking(move || run_cli(&url))
        .await
        .unwrap();
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
}

#[tokio::test]
async fn denied_request_exits_3_with_no_stdout() {
    let (url, _state) = start_mock(true).await;
    let out = tokio::task::spawn_blocking(move || run_cli(&url))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("denied"), "{stderr}");
    assert!(stderr.contains("not today"), "{stderr}");
}

#[test]
fn missing_url_is_config_error_exit_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_keychute"))
        .args(["request", "x"])
        .env_remove("KEYCHUTE_URL")
        .env_remove("KEYCHUTE_TOKEN")
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("KEYCHUTE_URL"));
}
