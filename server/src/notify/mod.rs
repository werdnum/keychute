//! Notifier trait, Pushover impl, and the background sweeper.
//!
//! The access-request row is the outbox: pushes are retried every sweep until
//! `push_delivered_at` is set (addendum #10 — the attempts counter is
//! telemetry, never an abandonment threshold). The sweeper also owns request
//! expiry and the purge lifecycle (addendum #11).

use crate::config::{Config, PushoverConfig};
use crate::db;
use crate::state::AppState;
use chrono::{Duration, Utc};
use keychute_types::Mechanism;
use std::sync::Arc;
use uuid::Uuid;

pub struct Notification {
    pub title: String,
    /// Server-vocabulary only: client name, secret name, tier, mechanism.
    pub message: String,
    pub url: Option<String>,
    pub url_title: Option<String>,
}

#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, n: &Notification) -> anyhow::Result<()>;

    /// False for the no-op notifier: callers must not record a "delivered"
    /// push (or bother retrying) when nothing can actually be sent.
    fn is_real(&self) -> bool {
        true
    }
}

/// No-op notifier used when pushover is not configured. `send` succeeds so
/// callers need no special-casing, but `is_real()` is false: requests keep
/// `push_delivered_at` NULL and the sweeper skips resend attempts.
pub struct NullNotifier;

#[async_trait::async_trait]
impl Notifier for NullNotifier {
    async fn send(&self, _n: &Notification) -> anyhow::Result<()> {
        Ok(())
    }

    fn is_real(&self) -> bool {
        false
    }
}

/// Pushover notifier. Posts form-encoded messages to
/// `{base_url}/1/messages.json`.
pub struct PushoverNotifier {
    base_url: String,
    token: String,
    user_key: String,
    http: reqwest::Client,
}

impl PushoverNotifier {
    pub fn new(base_url: String, token: String, user_key: String) -> PushoverNotifier {
        PushoverNotifier {
            base_url,
            token,
            user_key,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl Notifier for PushoverNotifier {
    async fn send(&self, n: &Notification) -> anyhow::Result<()> {
        let url = format!("{}/1/messages.json", self.base_url.trim_end_matches('/'));
        let mut form: Vec<(&str, &str)> = vec![
            ("token", self.token.as_str()),
            ("user", self.user_key.as_str()),
            ("title", n.title.as_str()),
            ("message", n.message.as_str()),
        ];
        if let Some(u) = &n.url {
            form.push(("url", u.as_str()));
        }
        if let Some(t) = &n.url_title {
            form.push(("url_title", t.as_str()));
        }
        let resp = self.http.post(&url).form(&form).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("pushover returned {}", resp.status());
        }
        Ok(())
    }
}

/// Resolve a credential from an inline value or a file path. Trailing
/// whitespace/newlines in files are trimmed.
fn load_credential(
    what: &str,
    value: &Option<String>,
    path: &Option<std::path::PathBuf>,
) -> anyhow::Result<String> {
    if let Some(v) = value {
        return Ok(v.clone());
    }
    if let Some(p) = path {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("reading {what} from {}: {e}", p.display()))?;
        return Ok(raw.trim().to_owned());
    }
    anyhow::bail!("pushover {what} missing (value or *_path)")
}

fn build_pushover(cfg: &PushoverConfig) -> anyhow::Result<PushoverNotifier> {
    let token = load_credential("token", &cfg.token, &cfg.token_path)?;
    let user_key = load_credential("user_key", &cfg.user_key, &cfg.user_key_path)?;
    Ok(PushoverNotifier::new(cfg.base_url.clone(), token, user_key))
}

/// Build the notifier. A pushover section that is present but broken
/// (unreadable token file, missing credentials) fails startup rather than
/// silently degrading to no notifications; an absent section is an explicit
/// choice and gets the (loudly logged) NullNotifier.
pub fn build_notifier(config: &Config) -> anyhow::Result<Arc<dyn Notifier>> {
    match &config.pushover {
        Some(cfg) => {
            let n =
                build_pushover(cfg).map_err(|e| anyhow::anyhow!("pushover misconfigured: {e}"))?;
            Ok(Arc::new(n))
        }
        None => {
            tracing::warn!("pushover not configured; approval notifications disabled");
            Ok(Arc::new(NullNotifier))
        }
    }
}

/// Compose the approval push for a pending request. Server vocabulary ONLY:
/// client name, mechanism, tier label, and the secret label — which must be
/// `"a not-yet-stored secret"` when the name does not match a stored secret
/// (addendum #5) — plus the approval link. Never client context.
pub fn request_notification(
    external_url: &str,
    request_id: Uuid,
    client_name: &str,
    mechanism: Mechanism,
    secret_label: &str,
) -> Notification {
    Notification {
        title: "Keychute approval needed".to_owned(),
        message: format!(
            "{client_name} requests {} access to {secret_label} — {}",
            mechanism.as_str(),
            mechanism.tier().human_label(),
        ),
        url: Some(format!(
            "{}/ui/requests/{request_id}",
            external_url.trim_end_matches('/')
        )),
        url_title: Some("Review request".to_owned()),
    }
}

/// The push label for a request's secret: its name when stored, else the
/// generic label (addendum #5).
pub async fn secret_push_label(db: &sqlx::PgPool, secret_name: &str) -> anyhow::Result<String> {
    Ok(match db::get_secret_by_name(db, secret_name).await? {
        Some(s) => s.name,
        None => "a not-yet-stored secret".to_owned(),
    })
}

const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// Shared with the create-request handler's initial-push dedup.
pub(crate) const PUSH_DEDUP_WINDOW_SECONDS: i64 = 60;
const CONTEXT_RETENTION_HOURS: i64 = 24;

/// Spawn the background sweeper: every 30 s — (a) expire stale pending
/// requests (waking wait-endpoint pollers), (b) retry undelivered approval
/// pushes with dedup, (c) purge lifecycle (passthrough payloads, terminal
/// request context, stale grant_reads).
pub fn spawn_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = sweep_once(&state).await {
                tracing::warn!(error = %err, "sweep failed");
            }
        }
    });
}

async fn sweep_once(state: &AppState) -> anyhow::Result<()> {
    let now = Utc::now();

    // (a) Expire pending requests past their deadline; waiting clients must
    // observe the transition.
    let expired = db::expire_stale(&state.db, now).await?;
    if expired > 0 {
        tracing::info!(count = expired, "expired stale access requests");
        state.resolve_notify.notify_waiters();
    }

    // (b) Push retry. Every pending request without a recorded delivery is
    // retried each sweep (attempts counter is telemetry only). With no real
    // notifier nothing can be delivered: skip the loop entirely rather than
    // spinning on rows that will never be marked delivered.
    let pending = if state.notifier.is_real() {
        db::list_pending_needing_push(&state.db, i32::MAX).await?
    } else {
        Vec::new()
    };
    for row in pending {
        let dedup = db::ui_ext::recent_duplicate_push(
            &state.db,
            &row,
            now - Duration::seconds(PUSH_DEDUP_WINDOW_SECONDS),
        )
        .await?;
        if dedup {
            continue;
        }
        let Some(mechanism) = Mechanism::from_str_opt(&row.mechanism) else {
            tracing::warn!(request_id = %row.id, "unknown mechanism on request row");
            continue;
        };
        let label = secret_push_label(&state.db, &row.secret_name).await?;
        let n = request_notification(
            &state.config.external_url,
            row.id,
            &row.client_name,
            mechanism,
            &label,
        );
        db::increment_push_attempts(&state.db, row.id).await?;
        match state.notifier.send(&n).await {
            Ok(()) => db::mark_push_delivered(&state.db, row.id).await?,
            Err(err) => {
                tracing::warn!(request_id = %row.id, error = %err, "push delivery failed");
            }
        }
    }

    // (c) Purge lifecycle (addendum #11).
    let replay_window = state.config.limits.replay_window_seconds;
    db::sweep_purge_passthroughs(&state.db, now, replay_window).await?;
    db::purge_request_context(&state.db, now - Duration::hours(CONTEXT_RETENTION_HOURS)).await?;
    db::ui_ext::delete_stale_grant_reads(&state.db, now - Duration::seconds(replay_window)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn null_notifier_is_not_real_and_pushover_is() {
        assert!(!NullNotifier.is_real());
        let p = PushoverNotifier::new("https://api.pushover.net".into(), "t".into(), "u".into());
        assert!(p.is_real());
    }

    #[test]
    fn broken_pushover_config_is_an_error() {
        // Unreadable token_path: startup must fail, not degrade to NullNotifier.
        let cfg = PushoverConfig {
            base_url: "https://api.pushover.net".into(),
            token: None,
            token_path: Some("/nonexistent/keychute-pushover-token".into()),
            user_key: Some("u".into()),
            user_key_path: None,
        };
        assert!(build_pushover(&cfg).is_err());
        // Missing credentials entirely is also an error.
        let cfg = PushoverConfig {
            base_url: "https://api.pushover.net".into(),
            token: None,
            token_path: None,
            user_key: None,
            user_key_path: None,
        };
        assert!(build_pushover(&cfg).is_err());
    }

    #[test]
    fn notification_vocabulary() {
        let id = Uuid::from_u128(7);
        let n = request_notification(
            "https://keychute.example.dev/",
            id,
            "k8s-agent",
            Mechanism::CliRead,
            "a not-yet-stored secret",
        );
        assert_eq!(n.title, "Keychute approval needed");
        assert!(n.message.contains("k8s-agent"));
        assert!(n.message.contains("cli-read"));
        assert!(n.message.contains("a not-yet-stored secret"));
        assert!(n.message.contains("tier 2"));
        assert_eq!(
            n.url.as_deref(),
            Some(format!("https://keychute.example.dev/ui/requests/{id}").as_str())
        );
        assert_eq!(n.url_title.as_deref(), Some("Review request"));
    }

    #[tokio::test]
    async fn pushover_posts_correct_form_fields() {
        let captured: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_writer = captured.clone();
        let app = axum::Router::new().route(
            "/1/messages.json",
            axum::routing::post(move |body: String| {
                let captured = captured_writer.clone();
                async move {
                    let form: HashMap<String, String> =
                        url::form_urlencoded::parse(body.as_bytes())
                            .into_owned()
                            .collect();
                    captured.lock().unwrap().push(form);
                    axum::Json(serde_json::json!({"status": 1}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let notifier = PushoverNotifier::new(
            format!("http://{addr}"),
            "app-token".into(),
            "user-key".into(),
        );
        notifier
            .send(&Notification {
                title: "Keychute approval needed".into(),
                message: "family-assistant requests brokered access".into(),
                url: Some("https://keychute.example.dev/ui/requests/abc".into()),
                url_title: Some("Review request".into()),
            })
            .await
            .unwrap();

        let forms = captured.lock().unwrap();
        assert_eq!(forms.len(), 1);
        let f = &forms[0];
        assert_eq!(f.get("token").map(String::as_str), Some("app-token"));
        assert_eq!(f.get("user").map(String::as_str), Some("user-key"));
        assert_eq!(
            f.get("title").map(String::as_str),
            Some("Keychute approval needed")
        );
        assert_eq!(
            f.get("message").map(String::as_str),
            Some("family-assistant requests brokered access")
        );
        assert_eq!(
            f.get("url").map(String::as_str),
            Some("https://keychute.example.dev/ui/requests/abc")
        );
        assert_eq!(
            f.get("url_title").map(String::as_str),
            Some("Review request")
        );
    }

    #[tokio::test]
    async fn pushover_send_fails_on_http_error() {
        let app = axum::Router::new().route(
            "/1/messages.json",
            axum::routing::post(|| async { axum::http::StatusCode::BAD_REQUEST }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let notifier = PushoverNotifier::new(format!("http://{addr}"), "t".into(), "u".into());
        let err = notifier
            .send(&Notification {
                title: "t".into(),
                message: "m".into(),
                url: None,
                url_title: None,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("400"));
    }
}
