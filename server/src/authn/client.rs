//! Machine-client authentication.
//!
//! A bearer token is tried first as a static API token (SHA-256 hex against
//! `clients.api_token_sha256`), then — when `tokenreview_url` is configured —
//! as a Kubernetes service-account token via TokenReview (addendum #3).
//!
//! All failures collapse to a uniform 401 `unauthenticated`; disabled clients
//! are indistinguishable from unknown ones.

use crate::api::error::ApiFailure;
use crate::crypto;
use crate::db::api_ext;
use crate::db::ClientRow;
use crate::state::AppState;
use axum::http::HeaderMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// A successfully authenticated machine client.
#[derive(Debug, Clone)]
pub struct AuthedClient {
    pub row: ClientRow,
}

impl AuthedClient {
    pub fn name(&self) -> &str {
        &self.row.name
    }
}

/// Authenticate the caller from the `Authorization: Bearer` header.
pub async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthedClient, ApiFailure> {
    let token = bearer_token(headers).ok_or(ApiFailure::Unauthenticated)?;

    // 1. Static API token: SHA-256 hex lookup. The SQL equality fetch is a
    //    candidate lookup only; the full hash is re-compared in constant time
    //    below (see api_ext::get_client_by_token_hash for the timing note).
    let presented_hash = hex::encode(Sha256::digest(token.as_bytes()));
    if let Some(row) = api_ext::get_client_by_token_hash(&state.db, &presented_hash).await? {
        let stored = row.api_token_sha256.as_deref().unwrap_or("");
        let stored_bytes = hex::decode(stored.to_ascii_lowercase()).unwrap_or_default();
        let presented_bytes = hex::decode(&presented_hash).expect("hex encode roundtrip");
        if crypto::ct_eq(&stored_bytes, &presented_bytes) && row.enabled {
            return Ok(AuthedClient { row });
        }
        return Err(ApiFailure::Unauthenticated);
    }

    // 2. Kubernetes TokenReview.
    if state.config.tokenreview_url.is_some() {
        return tokenreview_authenticate(state, token).await;
    }

    Err(ApiFailure::Unauthenticated)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[derive(Deserialize, Default)]
struct TokenReviewResponse {
    #[serde(default)]
    status: TokenReviewStatus,
}

#[derive(Deserialize, Default)]
struct TokenReviewStatus {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    user: TokenReviewUser,
}

#[derive(Deserialize, Default)]
struct TokenReviewUser {
    #[serde(default)]
    username: String,
}

/// HTTP client for TokenReview calls; built once (config is process-static).
fn tokenreview_http(state: &AppState) -> Result<&'static reqwest::Client, ApiFailure> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(ca_path) = &state.config.tokenreview_ca_path {
        let pem = std::fs::read(ca_path)
            .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("reading tokenreview CA: {e}")))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("parsing tokenreview CA: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder
        .build()
        .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("building tokenreview client: {e}")))?;
    Ok(CLIENT.get_or_init(|| client))
}

async fn tokenreview_authenticate(
    state: &AppState,
    token: &str,
) -> Result<AuthedClient, ApiFailure> {
    let url = state
        .config
        .tokenreview_url
        .as_deref()
        .ok_or(ApiFailure::Unauthenticated)?;

    // spec.audiences = union of all configured client SA audiences.
    let audiences: Vec<&str> = {
        let mut a: Vec<&str> = state
            .config
            .clients
            .iter()
            .filter_map(|c| c.auth.service_account.as_ref())
            .map(|sa| sa.audience.as_str())
            .collect();
        a.sort_unstable();
        a.dedup();
        a
    };
    if audiences.is_empty() {
        return Err(ApiFailure::Unauthenticated);
    }

    let body = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": { "token": token, "audiences": audiences },
    });

    let mut req = tokenreview_http(state)?.post(url).json(&body);
    if let Some(path) = &state.config.tokenreview_token_path {
        let reviewer_token = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| ApiFailure::Internal(anyhow::anyhow!("reading tokenreview token: {e}")))?;
        req = req.bearer_auth(reviewer_token.trim());
    }

    let resp = req.send().await.map_err(|e| {
        // Never include the reviewed token in errors; reqwest errors don't
        // carry the body we sent.
        ApiFailure::Internal(anyhow::anyhow!("tokenreview call failed: {e}"))
    })?;
    if !resp.status().is_success() {
        return Err(ApiFailure::Unauthenticated);
    }
    let review: TokenReviewResponse = resp.json().await.map_err(|_| ApiFailure::Unauthenticated)?;
    if !review.status.authenticated || review.status.user.username.is_empty() {
        return Err(ApiFailure::Unauthenticated);
    }

    // Addendum #3: the unique enabled client whose sa_subject equals the
    // authenticated username and whose sa_audience is among the audiences the
    // API server validated.
    let candidates = api_ext::get_clients_by_sa_subject(&state.db, &review.status.user.username)
        .await?
        .into_iter()
        .filter(|c| {
            c.enabled
                && c.sa_audience
                    .as_deref()
                    .is_some_and(|aud| review.status.audiences.iter().any(|a| a == aud))
        })
        .collect::<Vec<_>>();
    match candidates.len() {
        1 => Ok(AuthedClient {
            row: candidates.into_iter().next().expect("len checked"),
        }),
        _ => Err(ApiFailure::Unauthenticated),
    }
}
