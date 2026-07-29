//! Client-initiated secret deposit: `POST /v1/secrets`.
//!
//! The one write in the client API that carries credential bytes INTO
//! Keychute rather than out of it. Deliberately narrow (DESIGN §2 — a
//! misbehaving agent must not be able to touch credentials it was never
//! given):
//!
//! - **Opt-in per client.** `may_store_secrets` in the client's config block
//!   (migration 0006), default false, so enabling the endpoint changes nothing
//!   for existing deployments.
//! - **Create-only.** An existing name is a 409, never a rotation: a client
//!   cannot replace credential bytes an operator reviewed, and cannot silently
//!   substitute the credential behind a standing grant. Rotation stays on
//!   `POST /ui/secrets` behind human auth.
//! - **Tier capped.** The deposited `max_tier` defaults to `brokered` (the
//!   tightest) and may not exceed the depositing client's own cap, so a
//!   deposit cannot mint a secret more releasable than its depositor.
//! - **No tags.** Tag membership selects policy rows; a client that could tag
//!   its own deposit could choose which approval rules apply to it.
//! - **Rate capped.** `limits.max_deposits_per_hour_per_client` bounds how much
//!   operator attention one client can spend (every deposit pushes).
//!
//! The deposit itself needs no approval — nothing is released — but it is
//! audited (`secret-created`, actor `client:<name>`) and pushed to the
//! operator, because an unexpected credential appearing in the store is
//! exactly the kind of thing they want to notice.

use crate::api::error::ApiFailure;
use crate::authn::client::authenticate_client;
use crate::crypto::AadContext;
use crate::db;
use crate::db::ui_ext::StoreSecretParams;
use crate::injection::validate_injection;
use crate::notify::Notification;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use keychute_types::{SecretEncoding, StoreSecretRequest, StoreSecretResponse, Tier};
use secrecy::SecretBox;
use uuid::Uuid;
use zeroize::Zeroize;

/// Secret names travel into Pushover messages and audit rows as server
/// vocabulary, and are typed back by operators; keep them boring.
const MAX_NAME_BYTES: usize = 128;
/// Rendered (escaped) in the operator's secrets list.
const MAX_DESCRIPTION_BYTES: usize = 1024;
/// Credentials, not files. Generous for a PEM bundle, far below any body cap.
const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Bound on the encoded field before decoding, so an oversize base64 blob is
/// rejected without allocating its decoded form.
const MAX_ENCODED_VALUE_BYTES: usize = 4 * MAX_VALUE_BYTES / 3 + 4096;
/// Rolling window for the per-client deposit rate cap
/// (`limits.max_deposits_per_hour_per_client`).
const DEPOSIT_RATE_WINDOW_HOURS: i32 = 1;

/// A deposited name must be a plain identifier: it is echoed in pushes and in
/// the operator UI, and it is the key an approval decision is made against.
fn validate_name(name: &str) -> Result<(), ApiFailure> {
    if name.is_empty() {
        return Err(ApiFailure::InvalidRequest("name is required"));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(ApiFailure::RequestTooLarge("name too long"));
    }
    let ok = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.starts_with('.');
    if !ok {
        return Err(ApiFailure::InvalidRequest(
            "name must be ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

/// POST /v1/secrets
pub async fn store(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiFailure> {
    let client = authenticate_client(&state, &headers).await?;
    let parsed: Result<StoreSecretRequest, _> = serde_json::from_slice(&body);
    // The raw JSON body holds the plaintext too. Wipe it as soon as it has been
    // parsed — including on a parse failure, where the bytes are just as
    // sensitive. Best-effort by nature: `try_into_mut` only succeeds while this
    // is the sole owner of the buffer, and the bytes upstream of us (TLS and
    // socket read buffers) were never ours to clear. That is the same bound the
    // approval-form ingestion path works under.
    wipe(body);
    let mut req = parsed.map_err(|_| ApiFailure::InvalidRequest("malformed request body"))?;
    // The parsed struct owns its own copy: move it into a buffer that zeroizes
    // on drop, whichever way the handler exits.
    let value_field = zeroize::Zeroizing::new(std::mem::take(&mut req.value));
    store_inner(&state, &client, &req, &value_field).await
}

/// Zero a request body we are done with, if we hold the only reference to it.
fn wipe(body: Bytes) {
    if let Ok(mut owned) = body.try_into_mut() {
        owned.as_mut().zeroize();
    }
}

async fn store_inner(
    state: &AppState,
    client: &crate::authn::client::AuthedClient,
    req: &StoreSecretRequest,
    value_field: &str,
) -> Result<Response, ApiFailure> {
    if !client.row.may_store_secrets {
        // Server vocabulary only, and the same shape a policy refusal takes,
        // so a wrapper's "denied" branch fires for both.
        return Err(ApiFailure::PolicyDenied(
            "client is not permitted to store secrets".into(),
        ));
    }

    let name = req.name.trim().to_owned();
    validate_name(&name)?;
    if req.description.len() > MAX_DESCRIPTION_BYTES {
        return Err(ApiFailure::RequestTooLarge("description too long"));
    }
    if value_field.is_empty() {
        return Err(ApiFailure::InvalidRequest("value is required"));
    }
    if value_field.len() > MAX_ENCODED_VALUE_BYTES {
        return Err(ApiFailure::RequestTooLarge("value too large"));
    }
    let mut plaintext: Vec<u8> = match req.encoding {
        SecretEncoding::Utf8 => value_field.as_bytes().to_vec(),
        SecretEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(value_field.as_bytes())
            .map_err(|_| ApiFailure::InvalidRequest("value is not valid base64"))?,
    };
    if plaintext.len() > MAX_VALUE_BYTES {
        plaintext.zeroize();
        return Err(ApiFailure::RequestTooLarge("value too large"));
    }
    if plaintext.is_empty() {
        return Err(ApiFailure::InvalidRequest("value is required"));
    }
    let value = SecretBox::new(plaintext.as_slice().into());
    plaintext.zeroize();

    // A deposit may not out-rank its depositor: a tier-2 client cannot mint a
    // secret that a tier-3 mechanism would be allowed to release.
    let client_max = Tier::from_int(client.row.max_tier)
        .ok_or_else(|| ApiFailure::Internal(anyhow::anyhow!("client has an unknown max_tier")))?;
    let max_tier = req.max_tier.unwrap_or(Tier::Brokered);
    if max_tier > client_max {
        return Err(ApiFailure::InvalidRequest(
            "max_tier exceeds the client's own maximum tier",
        ));
    }

    let (injection_kind, injection_header, injection_username) = validate_injection(
        req.injection_kind.as_deref().unwrap_or("bearer"),
        req.injection_header.as_deref().filter(|h| !h.is_empty()),
    )
    .map_err(ApiFailure::InvalidRequest)?;

    let secret_id = Uuid::new_v4();
    let keyset = &state.keyset;
    let stored = db::create_secret_from_client(
        &state.db,
        StoreSecretParams {
            secret_id,
            name: name.clone(),
            description: req.description.trim().to_owned(),
            max_tier: max_tier.as_int(),
            injection_kind,
            injection_header,
            injection_username,
            // Sealed inside the insert transaction, under the KEK shared lock
            // (addendum #19).
            seal: Box::new(move || {
                keyset.seal(
                    &value,
                    AadContext::SecretVersion {
                        secret_id,
                        version: 1,
                    },
                )
            }),
        },
        client.name(),
        // Rate cap: every deposit pushes the operator and adds a row they may
        // have to review, so an opted-in client that goes haywire — or is
        // prompt-injected into a loop — must not be able to bury them. Decided
        // inside the deposit's own transaction, under a per-client lock: a
        // check out here would let N concurrent deposits all read the same
        // pre-deposit count and all pass.
        db::DepositRate {
            max_per_window: state.config.limits.max_deposits_per_hour_per_client,
            window_hours: DEPOSIT_RATE_WINDOW_HOURS,
        },
    )
    .await?;
    let secret_id = match stored {
        db::DepositOutcome::Created(id) => id,
        db::DepositOutcome::NameTaken => return Err(ApiFailure::SecretExists),
        db::DepositOutcome::RateLimited => return Err(ApiFailure::TooManyDeposits),
    };

    // FYI push: nothing is pending, but a credential just appeared in the
    // store. Best-effort — the secret IS stored, so a push failure must not
    // turn into a client-visible error (and a retry would 409).
    let n = deposit_notification(&state.config.external_url, client.name(), &name, max_tier);
    if state.notifier.is_real() {
        match tokio::time::timeout(crate::notify::PUSH_SEND_TIMEOUT, state.notifier.send(&n)).await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "secret-deposit push failed"),
            Err(_) => tracing::warn!("secret-deposit push timed out"),
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(StoreSecretResponse {
            secret_id,
            name,
            version: 1,
        }),
    )
        .into_response())
}

/// Server vocabulary only (DESIGN §2/§6): client name, secret name, tier.
/// The secret name is safe here — unlike a request for a not-yet-stored
/// secret, this name IS a stored secret by the time the push goes out.
fn deposit_notification(
    external_url: &str,
    client_name: &str,
    secret_name: &str,
    max_tier: Tier,
) -> Notification {
    Notification {
        title: "Keychute secret stored".to_owned(),
        message: format!(
            "{client_name} stored a new secret {secret_name} with maximum tier {} — {}. \
             No approval was needed; releasing it still is.",
            max_tier.as_str(),
            max_tier.human_label(),
        ),
        url: Some(format!("{}/ui/secrets", external_url.trim_end_matches('/'))),
        url_title: Some("Review secrets".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain_identifiers() {
        assert!(validate_name("my-api-key").is_ok());
        assert!(validate_name("svc.token_v2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("emoji-🙂").is_err());
        // Newlines would forge structure in a push message.
        assert!(validate_name("a\nb").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name(&"n".repeat(MAX_NAME_BYTES)).is_ok());
        assert!(validate_name(&"n".repeat(MAX_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn deposit_push_is_server_vocabulary() {
        let n = deposit_notification(
            "https://keychute.example.dev/",
            "k8s-agent",
            "my-api-key",
            Tier::Brokered,
        );
        assert!(n.message.contains("k8s-agent"));
        assert!(n.message.contains("my-api-key"));
        assert!(n.message.contains("brokered"));
        assert_eq!(
            n.url.as_deref(),
            Some("https://keychute.example.dev/ui/secrets")
        );
    }
}
