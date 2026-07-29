//! `keychute store` against a local axum mock server: what goes on the wire,
//! and how the create-only conflict surfaces.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

#[derive(Clone)]
struct MockState {
    /// Every deposit body the endpoint saw, in order.
    bodies: Arc<Mutex<Vec<serde_json::Value>>>,
    /// Answer every deposit with 409 `secret-exists`.
    conflict: bool,
}

async fn store_secret(
    State(st): State<MockState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    st.bodies.lock().unwrap().push(body.clone());
    if st.conflict {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": {
                    "code": "secret-exists",
                    "message": "a secret with this name already exists; rotation is operator-only",
                },
            })),
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "secret_id": "33333333-3333-3333-3333-333333333333",
            "name": body["name"],
            "version": 1,
        })),
    )
}

async fn start_mock(conflict: bool) -> (String, MockState) {
    let state = MockState {
        bodies: Arc::new(Mutex::new(Vec::new())),
        conflict,
    };
    let app = Router::new()
        .route("/v1/secrets", post(store_secret))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

fn run_store(url: &str, args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keychute"))
        .args(args)
        .env("KEYCHUTE_URL", url)
        .env("KEYCHUTE_TOKEN", "test-token")
        .env_remove("KEYCHUTE_TOKEN_FILE")
        .env_remove("KEYCHUTE_CA_BUNDLE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run keychute binary");
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().expect("waiting for keychute")
}

async fn store_against(
    conflict: bool,
    args: Vec<String>,
    stdin: Vec<u8>,
) -> (std::process::Output, MockState) {
    let (url, state) = start_mock(conflict).await;
    let out = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_store(&url, &refs, &stdin)
    })
    .await
    .unwrap();
    (out, state)
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn store_sends_the_stdin_value_and_reports_on_stderr() {
    let (out, state) = store_against(
        false,
        args(&[
            "store",
            "minted-key",
            "--description",
            "minted by the agent",
            "--max-tier",
            "cooperating-client",
            "--injection-kind",
            "header",
            "--injection-header",
            "X-Api-Key",
        ]),
        b"s3kr1t-value\n".to_vec(),
    )
    .await;

    assert_eq!(out.status.code(), Some(0), "{:?}", out);
    // stdout stays free for pipelines; the confirmation is on stderr and
    // never contains the value.
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("stored minted-key"), "{stderr}");
    assert!(!stderr.contains("s3kr1t-value"), "{stderr}");

    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "one attempt, no retry");
    let b = &bodies[0];
    assert_eq!(b["name"], "minted-key");
    // The shell's trailing newline is not part of the credential.
    assert_eq!(b["value"], "s3kr1t-value");
    assert_eq!(b["encoding"], "utf8");
    assert_eq!(b["description"], "minted by the agent");
    assert_eq!(b["max_tier"], "cooperating-client");
    assert_eq!(b["injection_kind"], "header");
    assert_eq!(b["injection_header"], "X-Api-Key");
}

#[tokio::test]
async fn store_defaults_to_the_tightest_tier() {
    let (out, state) = store_against(false, args(&["store", "plain-key"]), b"v".to_vec()).await;
    assert_eq!(out.status.code(), Some(0));
    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(bodies[0]["max_tier"], "brokered");
    assert_eq!(bodies[0]["injection_kind"], "bearer");
}

#[tokio::test]
async fn non_utf8_values_are_sent_base64() {
    let (out, state) = store_against(
        false,
        args(&["store", "binary-key", "--raw"]),
        vec![0xff, 0x00, 0xfe],
    )
    .await;
    assert_eq!(out.status.code(), Some(0));
    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(bodies[0]["encoding"], "base64");
    assert_eq!(bodies[0]["value"], "/wD+");
}

#[tokio::test]
async fn raw_keeps_the_trailing_newline() {
    let (out, state) = store_against(
        false,
        args(&["store", "pem-key", "--raw"]),
        b"line-one\n".to_vec(),
    )
    .await;
    assert_eq!(out.status.code(), Some(0));
    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(bodies[0]["value"], "line-one\n");
}

#[tokio::test]
async fn conflict_exits_1_and_is_not_retried() {
    let (out, state) = store_against(true, args(&["store", "taken"]), b"v".to_vec()).await;

    // A conflict is neither a timeout nor a denial: the generic code, so a
    // wrapper surfaces it instead of re-requesting.
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    assert!(stderr.contains("rotate"), "{stderr}");
    // Retrying a create-only call could only ever conflict again.
    assert_eq!(state.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn empty_input_is_a_usage_error_before_any_request() {
    let (out, state) = store_against(false, args(&["store", "empty"]), b"\n".to_vec()).await;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("empty"), "{stderr}");
    assert!(state.bodies.lock().unwrap().is_empty());
}
