//! E2E harness for Keychute.
//!
//! Each test spawns a full stack: fresh Postgres database, tempdir with KEK
//! keyset + config YAML, a real `keychute-server` child process, plus fake
//! services — a TLS recording upstream (the proxy only speaks https to
//! origins) and a fake Pushover endpoint. Tests drive the system black-box
//! via the REST API, the operator UI (real CSRF flow), and the `keychute`
//! CLI binary, and assert against the DB and the fakes.

use anyhow::Context;
use base64::Engine;
use rand::RngCore;
use sha2::Digest;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

pub const OPERATOR_TOKEN: &str = "operator-token";
pub const FA_TOKEN: &str = "fa-token";
pub const K8S_TOKEN: &str = "k8s-token";

// ---------------------------------------------------------------------------
// Build once

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate lives in the workspace root")
        .to_path_buf()
}

/// Build the server + CLI binaries exactly once per test binary.
pub fn ensure_built() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        // The test binary links both ring and aws-lc-rs transitively; rustls
        // needs one process-level default provider before any TLS use.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        // The binaries under test must be prebuilt. Spawning `cargo build`
        // from inside `cargo test` nests cargo invocations against the same
        // target dir, which corrupts artifacts on filesystems with broken
        // flock ("failed to map object file"). So: verify freshness and fail
        // loudly with the command to run, rather than building here.
        assert_fresh_binaries();
    });
}

const PREBUILD_HINT: &str = "run `cargo build -p keychute-server -p keychute-cli && \
     touch target/debug/keychute-server target/debug/keychute` before \
     `cargo test -p keychute-e2e`";

/// Newest mtime under a source directory (`.rs`, `.sql`, `Cargo.toml`).
fn newest_source_mtime(dir: &Path, newest: &mut std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            newest_source_mtime(&path, newest);
            continue;
        }
        let interesting = path.extension().is_some_and(|e| e == "rs" || e == "sql")
            || path.file_name().is_some_and(|n| n == "Cargo.toml");
        if !interesting {
            continue;
        }
        if let Ok(m) = entry.metadata().and_then(|m| m.modified()) {
            if m > *newest {
                *newest = m;
            }
        }
    }
}

/// Both binaries must exist and be at least as new as every source file they
/// are built from — otherwise the suite would silently test stale code.
fn assert_fresh_binaries() {
    for bin in [server_bin(), cli_bin()] {
        assert!(bin.exists(), "{} missing: {PREBUILD_HINT}", bin.display());
    }
    let root = workspace_root();
    let mut newest_src = std::time::UNIX_EPOCH;
    for sub in ["server", "cli", "types", "migrations"] {
        newest_source_mtime(&root.join(sub), &mut newest_src);
    }
    // The workspace root manifests too: a root Cargo.toml/Cargo.lock
    // dependency bump changes what the binaries link without touching any
    // file under the four source dirs.
    for manifest in ["Cargo.toml", "Cargo.lock"] {
        if let Ok(m) = std::fs::metadata(root.join(manifest)) {
            if let Ok(t) = m.modified() {
                newest_src = newest_src.max(t);
            }
        }
    }
    for bin in [server_bin(), cli_bin()] {
        let built = std::fs::metadata(&bin)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        assert!(
            built >= newest_src,
            "{} is older than its sources — {PREBUILD_HINT}",
            bin.display()
        );
    }
}

pub fn server_bin() -> PathBuf {
    workspace_root().join("target/debug/keychute-server")
}

pub fn cli_bin() -> PathBuf {
    workspace_root().join("target/debug/keychute")
}

// ---------------------------------------------------------------------------
// Options

/// Limit knobs a test can override; everything else uses server defaults.
#[derive(Clone)]
pub struct SpawnOpts {
    pub max_pending_per_client: i64,
    pub max_waits_per_client: usize,
    pub request_expiry_seconds: i64,
    pub proxy_max_body_bytes: usize,
    pub replay_window_seconds: i64,
    /// Full replacement for the default `clients:` YAML block when set.
    pub clients_yaml: Option<String>,
}

impl Default for SpawnOpts {
    fn default() -> Self {
        SpawnOpts {
            max_pending_per_client: 10,
            max_waits_per_client: 5,
            request_expiry_seconds: 3600,
            proxy_max_body_bytes: 10 * 1024 * 1024,
            replay_window_seconds: 3,
            clients_yaml: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Fake services

/// One request as observed by the fake upstream.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Lowercased header names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

type Recorded = Arc<Mutex<Vec<RecordedRequest>>>;
type PushForms = Arc<Mutex<Vec<HashMap<String, String>>>>;

async fn record_and_respond(
    records: Recorded,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .unwrap_or_default();
    let rec = RecordedRequest {
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: bytes.to_vec(),
    };
    let path = rec.path.clone();
    records.lock().unwrap().push(rec);

    if path.ends_with("/redirect") {
        return (
            axum::http::StatusCode::FOUND,
            [(axum::http::header::LOCATION, "/elsewhere")],
            "redirecting",
        )
            .into_response();
    }
    if path.ends_with("/slow") {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({ "ok": true, "path": path })),
    )
        .into_response()
}

/// Start the TLS recording upstream. Returns (port, records, ca_pem path).
async fn start_fake_upstream(dir: &Path) -> anyhow::Result<(u16, Recorded, PathBuf)> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let ca_path = dir.join("upstream-ca.pem");
    std::fs::write(&ca_path, &cert_pem)?;

    let records: Recorded = Arc::new(Mutex::new(Vec::new()));
    let recorder = records.clone();
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let records = recorder.clone();
        record_and_respond(records, req)
    });

    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    )
    .await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .serve(app.into_make_service())
            .await
            .ok();
    });
    Ok((port, records, ca_path))
}

/// Start the fake Pushover endpoint. Returns (port, recorded form posts).
async fn start_fake_pushover() -> anyhow::Result<(u16, PushForms)> {
    let forms: PushForms = Arc::new(Mutex::new(Vec::new()));
    let writer = forms.clone();
    let app = axum::Router::new().route(
        "/1/messages.json",
        axum::routing::post(move |body: String| {
            let writer = writer.clone();
            async move {
                let parsed: HashMap<String, String> = url_decode_form(&body).into_iter().collect();
                writer.lock().unwrap().push(parsed);
                axum::Json(serde_json::json!({ "status": 1 }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    Ok((port, forms))
}

/// Minimal x-www-form-urlencoded decoding (avoids extra deps).
fn url_decode_form(body: &str) -> Vec<(String, String)> {
    fn decode(s: &str) -> String {
        let s = s.replace('+', " ");
        let mut out = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    body.split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// Keyset

fn b64_random_key() -> String {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    base64::engine::general_purpose::STANDARD.encode(k)
}

/// Write a keyset file. `keys` maps kek id -> base64 key; `active` selects
/// the wrapping key for new seals.
pub fn write_keyset(path: &Path, active: &str, keys: &[(&str, &str)], mac_key: &str) {
    let mut map = serde_json::Map::new();
    for (id, key) in keys {
        map.insert((*id).to_owned(), serde_json::json!(key));
    }
    let doc = serde_json::json!({ "active": active, "keys": map, "mac_key": mac_key });
    std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
}

// ---------------------------------------------------------------------------
// TestEnv

pub struct TestEnv {
    pub base_url: String,
    pub external_url: String,
    pub db: PgPool,
    pub db_name: String,
    pub admin_url: String,
    pub upstream_port: u16,
    pub upstream_requests: Recorded,
    pub pushover_forms: PushForms,
    pub dir: tempfile::TempDir,
    pub keyset_path: PathBuf,
    /// Original active KEK (base64) so rotation tests can keep it around.
    pub k1: String,
    pub mac_key: String,
    server_port: u16,
    config_path: PathBuf,
    child: Option<Child>,
    log_index: u32,
}

fn admin_database_url() -> String {
    std::env::var("E2E_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres@127.0.0.1:55432/postgres".to_owned())
}

fn replace_db_name(admin_url: &str, db: &str) -> String {
    let (base, params) = match admin_url.split_once('?') {
        Some((b, p)) => (b, Some(p)),
        None => (admin_url, None),
    };
    // Strip any path after the authority, then append the new database name.
    let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let mut out = format!("{}/{}", &base[..authority_end], db);
    if let Some(p) = params {
        out.push('?');
        out.push_str(p);
    }
    out
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().unwrap().port()
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

impl TestEnv {
    pub async fn spawn(opts: SpawnOpts) -> anyhow::Result<TestEnv> {
        ensure_built();

        // Fresh database.
        let admin_url = admin_database_url();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .context("connecting to admin database")?;
        let db_name = format!("e2e_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin)
            .await
            .context("creating test database")?;
        admin.close().await;
        let db_url = replace_db_name(&admin_url, &db_name);
        let db = PgPoolOptions::new()
            .max_connections(4)
            .connect(&db_url)
            .await
            .context("connecting to test database")?;

        let dir = tempfile::tempdir()?;

        // Keyset.
        let k1 = b64_random_key();
        let mac_key = b64_random_key();
        let keyset_path = dir.path().join("keyset.json");
        write_keyset(&keyset_path, "k1", &[("k1", &k1)], &mac_key);

        // Fakes.
        let (upstream_port, upstream_requests, ca_path) = start_fake_upstream(dir.path()).await?;
        let (pushover_port, pushover_forms) = start_fake_pushover().await?;

        // Config.
        let server_port = free_port();
        let external_url = format!("http://127.0.0.1:{server_port}");
        let clients_yaml = opts.clients_yaml.clone().unwrap_or_else(|| {
            format!(
                "clients:\n\
                 \x20 - name: family-assistant\n\
                 \x20   max_tier: trusted-client\n\
                 \x20   mechanisms: [brokered, autofill]\n\
                 \x20   auth:\n\
                 \x20     api_token_sha256: \"{fa}\"\n\
                 \x20 - name: k8s-agent\n\
                 \x20   max_tier: cooperating-client\n\
                 \x20   mechanisms: [cli-read]\n\
                 \x20   auth:\n\
                 \x20     api_token_sha256: \"{k8s}\"\n",
                fa = sha256_hex(FA_TOKEN),
                k8s = sha256_hex(K8S_TOKEN),
            )
        });
        let config = format!(
            "listen_addr: \"127.0.0.1:{server_port}\"\n\
             external_url: \"{external_url}\"\n\
             allow_insecure_http: true\n\
             kek_file: {keyset}\n\
             upstream_ca_path: {ca}\n\
             human_auth:\n\
             \x20 mode: static\n\
             \x20 static:\n\
             \x20   token_sha256: \"{operator_hash}\"\n\
             \x20   subject: \"andrew\"\n\
             {clients_yaml}\
             pushover:\n\
             \x20 base_url: \"http://127.0.0.1:{pushover_port}\"\n\
             \x20 token: \"t\"\n\
             \x20 user_key: \"u\"\n\
             limits:\n\
             \x20 max_pending_per_client: {max_pending}\n\
             \x20 max_waits_per_client: {max_waits}\n\
             \x20 wait_max_seconds: 300\n\
             \x20 request_expiry_seconds: {expiry}\n\
             \x20 proxy_max_body_bytes: {max_body}\n\
             \x20 proxy_stream_deadline_seconds: 300\n\
             \x20 replay_window_seconds: {replay}\n\
             \x20 max_proxy_streams_per_client: 8\n",
            keyset = keyset_path.display(),
            ca = ca_path.display(),
            operator_hash = sha256_hex(OPERATOR_TOKEN),
            max_pending = opts.max_pending_per_client,
            max_waits = opts.max_waits_per_client,
            expiry = opts.request_expiry_seconds,
            max_body = opts.proxy_max_body_bytes,
            replay = opts.replay_window_seconds,
        );
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, config)?;

        let mut env = TestEnv {
            base_url: format!("http://127.0.0.1:{server_port}"),
            external_url,
            db,
            db_name,
            admin_url,
            upstream_port,
            upstream_requests,
            pushover_forms,
            dir,
            keyset_path,
            k1,
            mac_key,
            server_port,
            config_path,
            child: None,
            log_index: 0,
        };
        env.start_server().await?;
        Ok(env)
    }

    fn db_url(&self) -> String {
        replace_db_name(&self.admin_url, &self.db_name)
    }

    /// Spawn (or respawn) the server child and wait for /healthz.
    pub async fn start_server(&mut self) -> anyhow::Result<()> {
        self.log_index += 1;
        let stdout = std::fs::File::create(
            self.dir
                .path()
                .join(format!("server-{}.out", self.log_index)),
        )?;
        let stderr = std::fs::File::create(
            self.dir
                .path()
                .join(format!("server-{}.err", self.log_index)),
        )?;
        let child = std::process::Command::new(server_bin())
            .env("KEYCHUTE_CONFIG", &self.config_path)
            .env("KEYCHUTE_DATABASE_URL", self.db_url())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .context("spawning keychute-server")?;
        self.child = Some(child);

        let health = format!("{}/healthz", self.base_url);
        let http = reqwest::Client::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(resp) = http.get(&health).send().await {
                if resp.status().is_success() {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                anyhow::bail!(
                    "server did not become healthy; logs:\n{}",
                    self.server_logs()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Kill the server child and wait for it.
    pub fn stop_server(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().ok();
            child.wait().ok();
        }
    }

    /// Restart the server against the same config + database.
    pub async fn restart_server(&mut self) -> anyhow::Result<()> {
        self.stop_server();
        self.start_server().await
    }

    /// Concatenated stdout+stderr of all server incarnations.
    pub fn server_logs(&self) -> String {
        let mut out = String::new();
        for i in 1..=self.log_index {
            for ext in ["out", "err"] {
                let p = self.dir.path().join(format!("server-{i}.{ext}"));
                if let Ok(mut f) = std::fs::File::open(&p) {
                    let mut s = String::new();
                    f.read_to_string(&mut s).ok();
                    out.push_str(&s);
                }
            }
        }
        out
    }

    // -- HTTP helpers -------------------------------------------------------

    /// API client with a bearer token; never follows redirects.
    pub fn client(&self, token: &str) -> ApiClient {
        ApiClient {
            base: self.base_url.clone(),
            token: token.to_owned(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    pub fn fa(&self) -> ApiClient {
        self.client(FA_TOKEN)
    }

    pub fn k8s(&self) -> ApiClient {
        self.client(K8S_TOKEN)
    }

    pub fn operator(&self) -> ApiClient {
        self.client(OPERATOR_TOKEN)
    }

    // -- UI flows -----------------------------------------------------------

    /// GET a UI page as the operator; asserts 200 and returns the HTML.
    pub async fn ui_get(&self, path: &str) -> anyhow::Result<String> {
        let resp = self.operator().get(path).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        anyhow::ensure!(status.is_success(), "GET {path} -> {status}: {body}");
        Ok(body)
    }

    /// POST a UI form as the operator with a valid Origin header.
    pub async fn ui_post(
        &self,
        path: &str,
        form: &[(&str, &str)],
    ) -> anyhow::Result<(reqwest::StatusCode, String)> {
        let resp = self
            .operator()
            .post(path)
            .header(reqwest::header::ORIGIN, &self.external_url)
            .form(form)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        Ok((status, body))
    }

    /// Approve a pending request through the real UI flow: fetch the page,
    /// extract the approve form's CSRF token, POST with extra form fields.
    pub async fn approve(&self, request_id: &str, extra: &[(&str, &str)]) -> anyhow::Result<()> {
        let page = self.ui_get(&format!("/ui/requests/{request_id}")).await?;
        let action = format!("/ui/requests/{request_id}/approve");
        let token = extract_csrf(&page, &action).context("approve form csrf token not found")?;
        // Hidden field recording whether the secret was stored when the page
        // rendered; a browser submits it, and the handler 409s if it went stale.
        // It is also part of the token's MAC input, so it must come from the
        // same render as the token above — the two cannot be mixed and matched.
        let present = extract_form_field(&page, &action, "secret_present")
            .context("approve form secret_present marker not found")?;
        let mut form: Vec<(&str, &str)> =
            vec![("csrf_token", &token), ("secret_present", &present)];
        form.extend_from_slice(extra);
        let (status, body) = self
            .ui_post(&format!("/ui/requests/{request_id}/approve"), &form)
            .await?;
        anyhow::ensure!(status.is_redirection(), "approve failed: {status}: {body}");
        Ok(())
    }

    pub async fn deny(&self, request_id: &str) -> anyhow::Result<()> {
        let page = self.ui_get(&format!("/ui/requests/{request_id}")).await?;
        let token = extract_csrf(&page, &format!("/ui/requests/{request_id}/deny"))
            .context("deny form csrf token not found")?;
        let (status, body) = self
            .ui_post(
                &format!("/ui/requests/{request_id}/deny"),
                &[("csrf_token", &token)],
            )
            .await?;
        anyhow::ensure!(status.is_redirection(), "deny failed: {status}: {body}");
        Ok(())
    }

    /// Revoke a grant through the grants page (per-grant CSRF token).
    pub async fn revoke(&self, grant_id: &str) -> anyhow::Result<()> {
        let page = self.ui_get("/ui/grants").await?;
        let token = extract_csrf(&page, &format!("/ui/grants/{grant_id}/revoke"))
            .context("revoke form csrf token not found")?;
        let (status, body) = self
            .ui_post(
                &format!("/ui/grants/{grant_id}/revoke"),
                &[("csrf_token", &token)],
            )
            .await?;
        anyhow::ensure!(status.is_redirection(), "revoke failed: {status}: {body}");
        Ok(())
    }

    /// Create (or rotate) a stored secret via the admin UI.
    pub async fn seed_secret(
        &self,
        name: &str,
        value: &str,
        max_tier: &str,
        injection_kind: &str,
        injection_header: &str,
    ) -> anyhow::Result<()> {
        let page = self.ui_get("/ui/secrets").await?;
        let token =
            extract_csrf(&page, "/ui/secrets").context("secrets form csrf token not found")?;
        let (status, body) = self
            .ui_post(
                "/ui/secrets",
                &[
                    ("csrf_token", &token),
                    ("name", name),
                    ("secret_value", value),
                    ("description", "seeded by e2e"),
                    ("max_tier", max_tier),
                    ("injection_kind", injection_kind),
                    ("injection_header", injection_header),
                ],
            )
            .await?;
        anyhow::ensure!(
            status.is_redirection(),
            "seed_secret failed: {status}: {body}"
        );
        Ok(())
    }

    /// Create a standing policy row via the UI form.
    /// `fields` are the non-CSRF form fields (see PolicyForm in ui/mod.rs).
    pub async fn create_policy(&self, fields: &[(&str, &str)]) -> anyhow::Result<()> {
        let page = self.ui_get("/ui/policies").await?;
        let token =
            extract_csrf(&page, "/ui/policies").context("policy form csrf token not found")?;
        let mut form: Vec<(&str, &str)> = vec![("csrf_token", &token)];
        form.extend_from_slice(fields);
        let (status, body) = self.ui_post("/ui/policies", &form).await?;
        anyhow::ensure!(
            status.is_redirection(),
            "create_policy failed: {status}: {body}"
        );
        Ok(())
    }

    // -- DB helpers ---------------------------------------------------------

    /// Audit kinds recorded for a request id, in insertion order.
    pub async fn audit_kinds_for_request(&self, request_id: uuid::Uuid) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT kind FROM audit_log WHERE request_id = $1 ORDER BY id",
        )
        .bind(request_id)
        .fetch_all(&self.db)
        .await
        .expect("audit query")
    }

    /// Send a raw HTTP/1.1 request (for request-targets reqwest would
    /// normalize away, e.g. literal `..` segments). Returns the raw response
    /// head + whatever body arrived promptly.
    pub async fn raw_http(&self, request: &str) -> anyhow::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.server_port)).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// Poll until `f` returns Some, or panic after `deadline`.
pub async fn poll_until<T, F, Fut>(what: &str, deadline: Duration, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let end = Instant::now() + deadline;
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() <= end, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.stop_server();
        // Best-effort database drop from a throwaway runtime on a fresh
        // thread (Drop is sync and may run inside a tokio context).
        let admin_url = self.admin_url.clone();
        let db_name = self.db_name.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            rt.block_on(async {
                let admin = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                    .ok()?;
                sqlx::query(&format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"))
                    .execute(&admin)
                    .await
                    .ok();
                admin.close().await;
                Some(())
            })
        })
        .join()
        .ok();
    }
}

// ---------------------------------------------------------------------------
// ApiClient

pub struct ApiClient {
    pub base: String,
    pub token: String,
    pub http: reqwest::Client,
}

impl ApiClient {
    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
    }

    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
    }

    /// POST /v1/access-requests with a JSON body; returns (status, body json).
    pub async fn create_request(
        &self,
        body: serde_json::Value,
    ) -> anyhow::Result<(reqwest::StatusCode, serde_json::Value)> {
        let resp = self.post("/v1/access-requests").json(&body).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        let json =
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
        Ok((status, json))
    }

    /// POST /v1/grants/{id}/read; returns (status, body json).
    pub async fn read_grant(
        &self,
        grant_id: &str,
        idem_key: &str,
    ) -> anyhow::Result<(reqwest::StatusCode, serde_json::Value)> {
        let resp = self
            .post(&format!("/v1/grants/{grant_id}/read"))
            .json(&serde_json::json!({ "idempotency_key": idem_key }))
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        let json =
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
        Ok((status, json))
    }
}

// ---------------------------------------------------------------------------
// HTML scraping

/// Extract the csrf token of the form whose `action` attribute equals
/// `action` (see [`extract_form_field`]).
pub fn extract_csrf(html: &str, action: &str) -> Option<String> {
    extract_form_field(html, action, "csrf_token")
}

/// Value of the first `name="<field>" value="…"` input inside the form whose
/// action is `action` — what a browser would submit for that field.
pub fn extract_form_field(html: &str, action: &str, field: &str) -> Option<String> {
    let marker = format!("action=\"{action}\"");
    let start = html.find(&marker)?;
    let rest = &html[start..];
    let needle = format!("name=\"{field}\" value=\"");
    let at = rest.find(&needle)? + needle.len();
    let rest = &rest[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Extract all request ids linked from the pending-requests page.
pub fn extract_request_ids(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("/ui/requests/") {
        let tail = &rest[at + "/ui/requests/".len()..];
        let id: String = tail
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
            .collect();
        if id.len() == 36 && !out.contains(&id) {
            out.push(id);
        }
        rest = tail;
    }
    out
}

// ---------------------------------------------------------------------------
// Request-body builders

pub fn cli_read_request(idem: &str, secret: &str, ttl: u64, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "idempotency_key": idem,
        "secret_name": secret,
        "mechanism": "cli-read",
        "constraints": { "ttl_seconds": ttl },
        "context": { "reason": reason },
    })
}

pub fn brokered_request(
    idem: &str,
    secret: &str,
    host: &str,
    port: u16,
    methods: &[&str],
    prefixes: &[&str],
    ttl: u64,
) -> serde_json::Value {
    serde_json::json!({
        "idempotency_key": idem,
        "secret_name": secret,
        "mechanism": "brokered",
        "constraints": {
            "origins": [{ "host": host, "port": port }],
            "methods": methods,
            "path_prefixes": prefixes,
            "ttl_seconds": ttl,
        },
        "context": { "reason": "e2e brokered" },
    })
}

pub fn autofill_request(idem: &str, secret: &str, origins: &[&str], ttl: u64) -> serde_json::Value {
    let origins: Vec<serde_json::Value> = origins
        .iter()
        .map(|h| serde_json::json!({ "host": h }))
        .collect();
    serde_json::json!({
        "idempotency_key": idem,
        "secret_name": secret,
        "mechanism": "autofill",
        "constraints": { "origins": origins, "ttl_seconds": ttl },
        "context": { "reason": "autofill e2e" },
    })
}
