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

/// TCP+TLS handshake bound. Pushover is a public HTTPS endpoint; anything
/// slower than this is a network fault, not a slow server.
const PUSH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Whole-request bound (connect + send + response headers + body). The push is
/// sent INLINE from the single background sweeper, so an unbounded request
/// would stall push retries, request expiry AND the ciphertext purge lifecycle.
/// A push that misses this window is retried on the next sweep anyway.
const PUSH_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Belt-and-braces bound applied around every `Notifier::send`, so a notifier
/// implementation that ignores or lacks its own timeout still cannot wedge the
/// sweep — nor, on the create path, the `push_lock` that serializes every
/// approval-requiring create. Slightly above `PUSH_REQUEST_TIMEOUT` so the
/// client's own (more informative) timeout normally wins.
pub(crate) const PUSH_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

impl PushoverNotifier {
    pub fn new(base_url: String, token: String, user_key: String) -> PushoverNotifier {
        let http = reqwest::Client::builder()
            .connect_timeout(PUSH_CONNECT_TIMEOUT)
            .timeout(PUSH_REQUEST_TIMEOUT)
            .build()
            // Same failure mode as `reqwest::Client::new()`: only a broken TLS
            // backend can get here, and that is not a recoverable runtime state.
            .expect("build pushover http client");
        PushoverNotifier {
            base_url,
            token,
            user_key,
            http,
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
/// whitespace/newlines in files are trimmed. An empty (or whitespace-only)
/// credential fails startup like a missing one: it would build a "real"
/// notifier whose every send fails authentication — a healthy-looking pod
/// that never alerts the operator.
fn load_credential(
    what: &str,
    value: &Option<String>,
    path: &Option<std::path::PathBuf>,
) -> anyhow::Result<String> {
    let (resolved, source) = if let Some(v) = value {
        (v.clone(), "value".to_owned())
    } else if let Some(p) = path {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("reading {what} from {}: {e}", p.display()))?;
        (raw.trim().to_owned(), p.display().to_string())
    } else {
        anyhow::bail!("pushover {what} missing (value or *_path)")
    };
    if resolved.trim().is_empty() {
        anyhow::bail!("pushover {what} from {source} is empty");
    }
    Ok(resolved)
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

/// Compose the FYI push for a request released automatically by a standing
/// `notify-only` policy (DESIGN §4 release engine). Nothing is pending: the
/// request is already approved and the grant already minted, so the wording
/// reports what happened and the link is labelled "View request" rather than
/// prompting the operator to approve something that is already resolved.
///
/// Same server-vocabulary discipline as [`request_notification`] (DESIGN §2/§6):
/// client name, mechanism, tier label, and the secret label — which must be
/// `"a not-yet-stored secret"` when the name does not match a stored secret
/// (addendum #5). Never client-supplied context.
pub fn release_notification(
    external_url: &str,
    request_id: Uuid,
    client_name: &str,
    mechanism: Mechanism,
    secret_label: &str,
) -> Notification {
    Notification {
        title: "Keychute access released".to_owned(),
        message: format!(
            "{client_name} was granted {} access to {secret_label} — {} — automatically under a standing notify-only policy. No approval is needed.",
            mechanism.as_str(),
            mechanism.tier().human_label(),
        ),
        url: Some(format!(
            "{}/ui/requests/{request_id}",
            external_url.trim_end_matches('/')
        )),
        url_title: Some("View request".to_owned()),
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
/// Stop STARTING new pushes once a sweep's push phase has run this long. The
/// queue walks serially and each row may burn `PUSH_SEND_TIMEOUT`, so an
/// unreachable notifier with a deep queue would otherwise hold `sweep_once`
/// (and therefore the next expiry + purge tick) for minutes. Unsent rows stay
/// undelivered and lead the next sweep's queue; worst case the phase runs
/// budget + one `PUSH_SEND_TIMEOUT`.
const PUSH_PHASE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// How long the sweeper keeps retrying an undelivered notify-only FYI push.
/// Unlike approval pushes these have no pending window to bound them, and a
/// days-old "access was released" note is noise, not information.
const FYI_RETRY_WINDOW_HOURS: i64 = 24;

/// Spawn the background sweeper: every 30 s — (a) expire stale pending
/// requests (waking wait-endpoint pollers), (b) purge lifecycle (passthrough
/// payloads, terminal request context, stale grant_reads), (c) retry
/// undelivered approval pushes with dedup.
///
/// Stops cleanly when `shutdown` flips to `true` (or its sender is dropped),
/// so a graceful shutdown is not held up by the next tick. Returns the join
/// handle so the caller can wait for the loop to exit.
pub fn spawn_sweeper(
    state: AppState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = sweep_once(&state).await {
                        tracing::warn!(error = %err, "sweep failed");
                    }
                }
                // `changed()` also resolves (with an error) once the sender is
                // dropped; either way the process is going away.
                _ = shutdown.changed() => {
                    tracing::info!("background sweeper stopping");
                    break;
                }
            }
        }
    })
}

async fn sweep_once(state: &AppState) -> anyhow::Result<()> {
    // ORDERING. The phases are independent, but they are NOT interchangeable:
    // the push phase is the only network-bound one, it walks the pending queue
    // serially, and each row can burn up to `PUSH_SEND_TIMEOUT`. With Pushover
    // slow or unreachable a single sweep can therefore run for minutes. So the
    // two DB-only phases (expiry, purge) run FIRST and the push queue LAST —
    // otherwise a stalled push would postpone the purge lifecycle, leaving
    // consumed passthrough ciphertext, terminal request context and stale
    // replay rows in the database well past their retention windows, which is
    // precisely what splitting the sweep into phases was meant to prevent.
    //
    // Every expiry/retention cutoff is evaluated on the DATABASE clock inside
    // the queries themselves (matching the replay predicate in
    // `begin_grant_use`), so there is no process-clock timestamp to go stale
    // across a minutes-long phase and no skew window in which a purge could
    // destroy state a replay is still entitled to. And EVERY phase runs on
    // every sweep — failures are collected and reported together rather than
    // `?`-ed out early, so one broken phase can never skip a later one.
    let mut errors: Vec<String> = Vec::new();
    if let Err(err) = expire_phase(state).await {
        errors.push(format!("expiry phase: {err:#}"));
    }
    if let Err(err) = purge_phase(state).await {
        errors.push(format!("purge phase: {err:#}"));
    }
    if let Err(err) = push_phase(state).await {
        errors.push(format!("push phase: {err:#}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("; "))
    }
}

/// (a) Expire pending requests past their deadline; waiting clients must
/// observe the transition.
async fn expire_phase(state: &AppState) -> anyhow::Result<()> {
    let expired = db::expire_stale(&state.db).await?;
    if expired > 0 {
        tracing::info!(count = expired, "expired stale access requests");
        state.resolve_notify.notify_waiters();
    }
    Ok(())
}

/// (c) Push retry. Every pending request without a recorded delivery is
/// retried each sweep (attempts counter is telemetry only), then undelivered
/// notify-only FYI pushes within their retry window. With no real notifier
/// nothing can be delivered: skip the loop entirely rather than spinning on
/// rows that will never be marked delivered. The whole phase respects
/// `PUSH_PHASE_BUDGET` so a dead notifier cannot stall the next sweep's
/// expiry and purge phases behind a deep queue.
async fn push_phase(state: &AppState) -> anyhow::Result<()> {
    if !state.notifier.is_real() {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + PUSH_PHASE_BUDGET;
    let pending = db::list_pending_needing_push(&state.db, i32::MAX).await?;
    let fyi = db::list_notify_only_needing_push(&state.db, FYI_RETRY_WINDOW_HOURS * 3600).await?;
    let mut skipped: usize = 0;
    for row in pending.iter().chain(fyi.iter()) {
        if tokio::time::Instant::now() >= deadline {
            skipped += 1;
            continue;
        }
        // One bad row must not abandon the rest of the queue.
        let sent = if row.notify_only {
            push_one_fyi(state, row).await
        } else {
            push_one(state, row).await
        };
        if let Err(err) = sent {
            tracing::warn!(request_id = %row.id, error = %err, "push retry failed");
        }
    }
    if skipped > 0 {
        tracing::warn!(
            skipped,
            budget_seconds = PUSH_PHASE_BUDGET.as_secs(),
            "push phase budget exhausted; remaining rows retry next sweep"
        );
    }
    Ok(())
}

/// FYI push for a notify-only release (migration 0006 outbox). No dedup: each
/// row reports a distinct release that already happened. The conditional claim
/// still guards against a concurrent create-path send marking the row
/// delivered while this sweep was preparing.
async fn push_one_fyi(state: &AppState, row: &db::AccessRequestRow) -> anyhow::Result<()> {
    let _push_guard = state.push_lock.lock().await;
    let Some(mechanism) = Mechanism::from_str_opt(&row.mechanism) else {
        tracing::warn!(request_id = %row.id, "unknown mechanism on request row");
        return Ok(());
    };
    // Same label shape as the create path's immediate FYI: quoted name when
    // stored, bare generic label otherwise (addendum #5).
    let label = match db::get_secret_by_name(&state.db, &row.secret_name).await? {
        Some(s) => format!("'{}'", s.name),
        None => "a not-yet-stored secret".to_owned(),
    };
    if !claim_for_fyi_push(&state.db, row.id).await? {
        return Ok(());
    }
    let n = release_notification(
        &state.config.external_url,
        row.id,
        &row.client_name,
        mechanism,
        &label,
    );
    match tokio::time::timeout(PUSH_SEND_TIMEOUT, state.notifier.send(&n)).await {
        Ok(Ok(())) => db::mark_push_delivered(&state.db, row.id).await?,
        Ok(Err(err)) => {
            tracing::warn!(request_id = %row.id, error = %err, "FYI push delivery failed");
        }
        Err(_) => {
            tracing::warn!(
                request_id = %row.id,
                timeout_seconds = PUSH_SEND_TIMEOUT.as_secs(),
                "FYI push delivery timed out"
            );
        }
    }
    Ok(())
}

async fn push_one(state: &AppState, row: &db::AccessRequestRow) -> anyhow::Result<()> {
    // Same serialization as the create path (state.push_lock): the sweep
    // must not race a concurrent create's dedup-check + send. The send below
    // is timeout-bounded, so the lock is held for a bounded time.
    let _push_guard = state.push_lock.lock().await;
    // Per-row `now`: a queue of slow pushes can take minutes, and the dedup
    // window must be measured against the moment THIS row is considered.
    let now = Utc::now();
    let dedup = db::ui_ext::recent_duplicate_push(
        &state.db,
        row,
        now - Duration::seconds(PUSH_DEDUP_WINDOW_SECONDS),
    )
    .await?;
    if dedup {
        // The operator was just told about an identical pending request,
        // so this one is covered. Record it as delivered (same as the
        // create path) — leaving it undelivered would re-select the row
        // every sweep and fire a duplicate push once the window ages out.
        db::mark_push_delivered(&state.db, row.id).await?;
        return Ok(());
    }
    let Some(mechanism) = Mechanism::from_str_opt(&row.mechanism) else {
        tracing::warn!(request_id = %row.id, "unknown mechanism on request row");
        return Ok(());
    };
    let label = secret_push_label(&state.db, &row.secret_name).await?;
    let n = request_notification(
        &state.config.external_url,
        row.id,
        &row.client_name,
        mechanism,
        &label,
    );
    // Conditional claim. The row was selected at the top of the phase, and the
    // dedup + label lookups above are round trips: the operator may have
    // approved, denied or let the request expire in that window. Bump the
    // attempts counter ONLY while the row is still pushable, and treat "no row"
    // as "resolved concurrently" — sending here would push an unactionable
    // "approval needed" prompt for an already-decided request.
    if !claim_for_push(&state.db, row.id).await? {
        return Ok(());
    }
    match tokio::time::timeout(PUSH_SEND_TIMEOUT, state.notifier.send(&n)).await {
        Ok(Ok(())) => db::mark_push_delivered(&state.db, row.id).await?,
        Ok(Err(err)) => {
            tracing::warn!(request_id = %row.id, error = %err, "push delivery failed");
        }
        // A timed-out push is a FAILED delivery: the row stays undelivered
        // (attempts already incremented) and is retried next sweep.
        Err(_) => {
            tracing::warn!(
                request_id = %row.id,
                timeout_seconds = PUSH_SEND_TIMEOUT.as_secs(),
                "push delivery timed out"
            );
        }
    }
    Ok(())
}

/// Increment `push_attempts` iff the request is still pending, unexpired and
/// undelivered — the same predicate `list_pending_needing_push` selects on.
/// False means the row is no longer pushable and the caller must not send.
/// Shared with the create path's initial push (`api::requests::create`), which
/// races the operator resolving the just-committed row.
pub(crate) async fn claim_for_push(db: &sqlx::PgPool, request_id: Uuid) -> anyhow::Result<bool> {
    let claimed: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE access_requests SET push_attempts = push_attempts + 1 \
         WHERE id = $1 AND state = 'pending' AND push_delivered_at IS NULL \
           AND expires_at > now() \
         RETURNING id",
    )
    .bind(request_id)
    .fetch_optional(db)
    .await?;
    Ok(claimed.is_some())
}

/// FYI counterpart of [`claim_for_push`]: increment `push_attempts` iff the
/// notify-only row's FYI push is still undelivered. Shared with the create
/// path's immediate FYI send, which races the sweeper.
pub(crate) async fn claim_for_fyi_push(
    db: &sqlx::PgPool,
    request_id: Uuid,
) -> anyhow::Result<bool> {
    let claimed: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE access_requests SET push_attempts = push_attempts + 1 \
         WHERE id = $1 AND notify_only AND push_delivered_at IS NULL \
         RETURNING id",
    )
    .bind(request_id)
    .fetch_optional(db)
    .await?;
    Ok(claimed.is_some())
}

/// (b) Purge lifecycle (addendum #11). Runs before the push phase so network
/// trouble at the notifier can never delay ciphertext deletion.
async fn purge_phase(state: &AppState) -> anyhow::Result<()> {
    let replay_window = state.config.limits.replay_window_seconds;
    db::sweep_purge_passthroughs(&state.db, replay_window).await?;
    db::purge_request_context(&state.db, CONTEXT_RETENTION_HOURS * 3600).await?;
    db::ui_ext::unpin_stale_grant_reads(&state.db, replay_window).await?;
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
        // Empty/whitespace-only credentials (e.g. an empty mounted Secret)
        // must fail startup too, not build a notifier that can never send.
        let cfg = PushoverConfig {
            base_url: "https://api.pushover.net".into(),
            token: Some("  ".into()),
            token_path: None,
            user_key: Some("u".into()),
            user_key_path: None,
        };
        assert!(build_pushover(&cfg).is_err());
        let empty_file = std::env::temp_dir().join("keychute-test-empty-pushover-user-key");
        std::fs::write(&empty_file, "\n").unwrap();
        let cfg = PushoverConfig {
            base_url: "https://api.pushover.net".into(),
            token: Some("t".into()),
            user_key: None,
            token_path: None,
            user_key_path: Some(empty_file.clone()),
        };
        let err = build_pushover(&cfg)
            .err()
            .expect("empty user_key file must fail");
        assert!(err.to_string().contains("empty"), "{err}");
        std::fs::remove_file(&empty_file).ok();
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

    #[test]
    fn release_notification_is_informational() {
        let id = Uuid::from_u128(9);
        let n = release_notification(
            "https://keychute.example.dev/",
            id,
            "family-assistant",
            Mechanism::Brokered,
            "github-pat",
        );
        // Never prompts for an approval that already happened.
        assert!(!n.title.to_lowercase().contains("approval"));
        assert!(!n.message.to_lowercase().contains("requests"));
        assert_eq!(n.title, "Keychute access released");
        assert!(n.message.contains("family-assistant"));
        assert!(n.message.contains("brokered"));
        assert!(n.message.contains("github-pat"));
        assert!(n.message.contains("tier 0"));
        assert!(n.message.contains("notify-only"));
        assert_eq!(
            n.url.as_deref(),
            Some(format!("https://keychute.example.dev/ui/requests/{id}").as_str())
        );
        assert_eq!(n.url_title.as_deref(), Some("View request"));
    }

    /// A peer that completes the TCP handshake and then never writes a byte —
    /// the exact shape that used to hang the sweeper forever.
    #[tokio::test]
    async fn pushover_send_times_out_against_a_silent_peer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                // Accept and hold the socket open without ever responding.
                held.push(sock);
            }
        });

        let notifier = PushoverNotifier::new(format!("http://{addr}"), "t".into(), "u".into());
        // Generous ceiling: a regression fails the test instead of hanging CI.
        let ceiling = PUSH_REQUEST_TIMEOUT + std::time::Duration::from_secs(20);
        let outcome = tokio::time::timeout(
            ceiling,
            notifier.send(&Notification {
                title: "t".into(),
                message: "m".into(),
                url: None,
                url_title: None,
            }),
        )
        .await
        .expect("send must return within its own timeout, not hang");
        assert!(outcome.is_err(), "silent peer must surface as an error");
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
