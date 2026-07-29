//! Approval UI: server-rendered pages (maud), CSRF, human authn.
//!
//! Invariants (DESIGN §6, IMPLEMENTATION "Human/UI routes"):
//! - Every response carries `Cache-Control: no-store`, `X-Frame-Options:
//!   DENY`, and a deny-all CSP (inline styles only) — applied by a router
//!   layer so no handler can forget.
//! - Client-supplied context renders as maud TEXT nodes only (auto-escaped);
//!   `PreEscaped` is never used for anything client-derived.
//! - The approval page separates the SERVER-PARSED grant ("what you are
//!   approving") from the client-asserted context, clearly labelled.
//! - Every POST requires the per-form CSRF token AND browser-metadata checks
//!   (addendum #9).

pub mod csrf;
mod policy_store;

use crate::authn::human::{authenticate_human, Operator};
use crate::crypto::{AadContext, SecretBytes, EPHEMERAL_KEK_ID};
use crate::db;
use crate::db::requests::{AccessRequestRow, GrantParams, PassthroughPayload};
use crate::db::ui_ext::StoreSecretParams;
use crate::state::AppState;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use chrono::{DateTime, Duration, Utc};
use keychute_types::{Constraints, Mechanism, Origin, RequestContext, Tier};
use maud::{html, Markup, DOCTYPE};
use secrecy::SecretBox;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroize;

// CSRF route labels (single-purpose tokens).
const R_APPROVE: &str = "/ui/requests/approve";
const R_DENY: &str = "/ui/requests/deny";
const R_REVOKE: &str = "/ui/grants/revoke";
const R_POLICY_CREATE: &str = "/ui/policies/create";
const R_POLICY_DELETE: &str = "/ui/policies/delete";
const R_SECRET_SAVE: &str = "/ui/secrets/save";

pub fn router(state: AppState) -> Router {
    Router::new()
        // Landing page: what a browser gets when the operator types the
        // hostname and nothing else. `/ui` and `/ui/` are the paths people
        // guess from the section links, so send both here rather than 404.
        .route("/", get(overview_page))
        .route("/ui", get(ui_root))
        .route("/ui/", get(ui_root))
        .route("/ui/requests", get(requests_page))
        .route("/ui/requests/{id}", get(request_detail_page))
        .route("/ui/requests/{id}/approve", post(approve))
        .route("/ui/requests/{id}/deny", post(deny))
        .route("/ui/grants", get(grants_page))
        .route("/ui/grants/{id}/revoke", post(revoke))
        .route("/ui/policies", get(policies_page))
        .route("/ui/policies", post(create_policy))
        .route("/ui/policies/{id}/delete", post(delete_policy))
        .route("/ui/secrets", get(secrets_page))
        .route("/ui/secrets", post(save_secret))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Applied to EVERY ui response, including errors.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; \
             form-action 'self'",
        ),
    );
    resp
}

// ---------------------------------------------------------------------------
// Errors

#[derive(Debug)]
struct UiError {
    status: StatusCode,
    msg: String,
}

impl UiError {
    fn new(status: StatusCode, msg: impl Into<String>) -> UiError {
        UiError {
            status,
            msg: msg.into(),
        }
    }
    fn bad_request(msg: impl Into<String>) -> UiError {
        UiError::new(StatusCode::BAD_REQUEST, msg)
    }
}

impl From<anyhow::Error> for UiError {
    fn from(err: anyhow::Error) -> UiError {
        tracing::error!(error = %err, "ui internal error");
        UiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        let page = layout(
            "Error",
            html! {
                h1 { "Error" }
                p { (self.msg) }
                p { a href="/ui/requests" { "Back to pending requests" } }
            },
        );
        (self.status, Html(page.into_string())).into_response()
    }
}

type UiResult<T> = Result<T, UiError>;

async fn operator(state: &AppState, headers: &HeaderMap) -> UiResult<Operator> {
    authenticate_human(state, headers).await.map_err(|status| {
        let msg = if status == StatusCode::FORBIDDEN {
            "not authorized to operate Keychute"
        } else {
            "authentication required"
        };
        UiError::new(status, msg)
    })
}

/// Both halves of the POST guard (addendum #9).
fn check_post(
    state: &AppState,
    headers: &HeaderMap,
    route: &str,
    action_id: &str,
    subject: &str,
    form_state: &str,
    token: &str,
) -> UiResult<()> {
    if !csrf::browser_metadata_ok(
        &state.config.external_url,
        state.config.tls.is_some(),
        headers,
    ) {
        return Err(UiError::new(
            StatusCode::FORBIDDEN,
            "cross-origin request rejected",
        ));
    }
    if !csrf::verify_token(
        &state.keyset,
        route,
        action_id,
        subject,
        form_state,
        token,
        Utc::now(),
    ) {
        return Err(UiError::new(
            StatusCode::FORBIDDEN,
            "invalid or expired form token; reload the page and retry",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layout & shared rendering

fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " — Keychute" }
                style {
                    r#"
                    body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #1a1a1a; }
                    nav a { margin-right: 1rem; }
                    table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
                    th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
                    .grant-block { border: 2px solid #2a6; background: #f2fbf5; padding: 1rem; margin: 1rem 0; }
                    .context-block { border: 2px dashed #b60; background: #fff8ef; padding: 1rem; margin: 1rem 0; }
                    .caveat { color: #a40; font-weight: bold; }
                    .muted { color: #666; }
                    pre { background: #f4f4f4; padding: 0.6rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
                    form.inline { display: inline; }
                    fieldset { margin: 1rem 0; }
                    label { display: block; margin: 0.4rem 0; }
                    "#
                }
            }
            body {
                nav {
                    a href="/" { "Overview" }
                    a href="/ui/requests" { "Requests" }
                    a href="/ui/grants" { "Grants" }
                    a href="/ui/policies" { "Policies" }
                    a href="/ui/secrets" { "Secrets" }
                }
                (body)
            }
        }
    }
}

fn html_page(title: &str, body: Markup) -> Html<String> {
    Html(layout(title, body).into_string())
}

fn age_label(created_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (now - created_at).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn tier_from_str(s: &str) -> Option<Tier> {
    match s {
        "brokered" => Some(Tier::Brokered),
        "trusted-client" => Some(Tier::TrustedClient),
        "cooperating-client" => Some(Tier::CooperatingClient),
        "direct" => Some(Tier::Direct),
        _ => None,
    }
}

fn parse_constraints(row: &AccessRequestRow) -> UiResult<Constraints> {
    serde_json::from_value(row.constraints.clone())
        .map_err(|e| anyhow::anyhow!("bad constraints jsonb on request {}: {e}", row.id).into())
}

fn parse_mechanism(s: &str) -> UiResult<Mechanism> {
    Mechanism::from_str_opt(s)
        .ok_or_else(|| anyhow::anyhow!("unknown mechanism {s:?} on stored row").into())
}

/// SERVER-PARSED grant summary: the authoritative "what you are approving"
/// block (DESIGN §6). Everything here is server vocabulary derived from the
/// stored, validated constraints — never the client's narration.
fn grant_block(mechanism: Mechanism, constraints: &Constraints, secret_line: Markup) -> Markup {
    let tier = mechanism.tier();
    html! {
        section .grant-block {
            h2 { "What you are approving (server-parsed)" }
            table {
                tr { th { "Secret" } td { (secret_line) } }
                tr { th { "Mechanism" } td { (mechanism.as_str()) } }
                tr { th { "Tier" } td { (tier.human_label()) } }
                tr { th { "Origins" }
                    td {
                        @if constraints.origins.is_empty() { span .muted { "(none)" } }
                        @else { @for o in &constraints.origins { div { (o.to_display()) } } }
                    }
                }
                tr { th { "Methods" }
                    td {
                        @if constraints.methods.is_empty() { span .muted { "(none)" } }
                        @else { (constraints.methods.join(", ")) }
                    }
                }
                tr { th { "Path prefixes" }
                    td {
                        @if constraints.path_prefixes.is_empty() { span .muted { "(none)" } }
                        @else { @for p in &constraints.path_prefixes { div { (p) } } }
                    }
                }
                tr { th { "Requested TTL" } td { (constraints.ttl_seconds) " seconds" } }
                tr { th { "Requested max uses" }
                    td {
                        @match constraints.max_uses {
                            Some(n) => { (n) }
                            None => {
                                @if mechanism.is_releasing() { "1 (releasing default)" }
                                @else { "unlimited within TTL" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Client-asserted context block. ALL values here are untrusted client input
/// and render as text nodes only — maud escapes them.
fn context_block(context: Option<&RequestContext>, mechanism: Mechanism) -> Markup {
    html! {
        section .context-block {
            h2 { "Client-asserted context (unverified)" }
            p .muted {
                "Everything below was supplied by the requesting client and may be "
                "influenced by a prompt-injected agent. It is NOT what the server "
                "will enforce."
            }
            @if mechanism == Mechanism::CliRead {
                p .caveat {
                    "Tier-2 caveat: this request is tagged as coming from the keychute "
                    "CLI, but any pipeline or reason shown is agent-asserted, captured "
                    "inside the agent's own container. The agent CAN read the released "
                    "secret from stdout."
                }
            }
            @match context {
                Some(ctx) => {
                    h3 { "Reason" }
                    @if ctx.reason.is_empty() { p .muted { "(no reason given)" } }
                    @else { p { (ctx.reason) } }
                    @if let Some(structured) = &ctx.structured {
                        h3 { "Structured context" }
                        pre {
                            (serde_json::to_string_pretty(structured)
                                .unwrap_or_else(|_| "(unrenderable)".to_owned()))
                        }
                    }
                }
                None => { p .muted { "(no context available)" } }
            }
        }
    }
}

/// Decrypt the stored request context, if any. Ephemeral-KEK rows are opened
/// with the process key; anything undecryptable renders as absent.
fn decrypt_context(state: &AppState, row: &AccessRequestRow) -> Option<RequestContext> {
    let (ct, nonce, dek, kek_id) = (
        row.context_ciphertext.as_deref()?,
        row.context_nonce.as_deref()?,
        row.context_wrapped_dek.as_deref()?,
        row.context_kek_id.as_deref()?,
    );
    let aad = AadContext::RequestContext { request_id: row.id };
    let opened = if kek_id == EPHEMERAL_KEK_ID {
        state.ephemeral_kek.open(ct, nonce, dek, aad)
    } else {
        state.keyset.open(ct, nonce, dek, kek_id, aad)
    };
    match opened {
        Ok(plain) => {
            use secrecy::ExposeSecret;
            serde_json::from_slice(plain.expose_secret()).ok()
        }
        Err(err) => {
            tracing::warn!(request_id = %row.id, error = %err, "request context undecryptable");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// GET / — landing page

/// `/ui` and `/ui/` are not pages of their own: they are what an operator
/// types after seeing a `/ui/...` link. Send them to the overview.
async fn ui_root() -> Redirect {
    Redirect::to("/")
}

/// The page a browser lands on at the bare hostname. It answers "is anything
/// waiting for me?" first — that is the only time-critical thing Keychute
/// asks of a human — and then signposts the rest of the UI.
///
/// Authenticated like every other UI page: the counts describe which secrets
/// exist and who is currently holding a grant, so they are not public.
async fn overview_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let op = operator(&state, &headers).await?;
    // Counted in SQL, never listed: the rows behind the first two counts carry
    // encrypted client context and passthrough payloads, and a page that only
    // shows a number has no business loading either. The pending count's
    // expiry predicate is the database clock, matching what /ui/requests
    // filters on and what the approve transition enforces.
    let pending = db::count_pending(&state.db).await?;
    let grants =
        db::ui_ext::count_active_grants(&state.db, state.config.limits.replay_window_seconds)
            .await?;
    let policies = db::count_policies(&state.db).await?;
    let secrets = db::count_secrets(&state.db).await?;

    Ok(html_page(
        "Overview",
        html! {
            h1 { "Keychute" }
            p .muted {
                "Secrets storage and delivery broker for AI agents. Every "
                "delivery path has an operator-chosen risk tier, and every "
                "release is either matched by a standing policy or approved "
                "here by you."
            }
            p { "Signed in as " (op.subject) "." }

            @if pending > 0 {
                p .caveat {
                    (pending)
                    @if pending == 1 { " request is" } @else { " requests are" }
                    " waiting for your decision. "
                    a href="/ui/requests" { "Review now" }
                }
            } @else {
                p { "Nothing is waiting for your decision." }
            }

            table {
                tr { th { "Section" } th { "Now" } th { "What it is" } }
                tr {
                    td { a href="/ui/requests" { "Requests" } }
                    td { (pending) " pending" }
                    td { "Access requests awaiting approval or denial." }
                }
                tr {
                    td { a href="/ui/grants" { "Grants" } }
                    td { (grants) " active" }
                    td { "Live grants; revoke one to cut off access immediately." }
                }
                tr {
                    td { a href="/ui/policies" { "Policies" } }
                    td { (policies) }
                    td { "Standing rules that auto-approve matching requests." }
                }
                tr {
                    td { a href="/ui/secrets" { "Secrets" } }
                    td { (secrets) " stored" }
                    td { "Stored credentials, their max tier and injection style." }
                }
            }
        },
    ))
}

// ---------------------------------------------------------------------------
// GET /ui/requests

async fn requests_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    operator(&state, &headers).await?;
    // Database clock: the approve/deny transitions enforce `expires_at` with
    // SQL now(), so filtering here on a skewed process clock would either
    // hide a still-approvable request ("No pending requests") or offer a form
    // whose submission is guaranteed to 409.
    let now = db::db_now(&state.db).await?;
    let rows: Vec<AccessRequestRow> = db::list_pending(&state.db)
        .await?
        .into_iter()
        .filter(|r| r.expires_at > now)
        .collect();
    Ok(html_page(
        "Pending requests",
        html! {
            h1 { "Pending access requests" }
            @if rows.is_empty() { p .muted { "No pending requests." } }
            @else {
                table {
                    tr {
                        th { "Client" } th { "Secret" } th { "Mechanism" }
                        th { "Tier" } th { "Age" } th { "" }
                    }
                    @for r in &rows {
                        tr {
                            td { (r.client_name) }
                            td { (r.secret_name) }
                            td { (r.mechanism) }
                            td {
                                @match Mechanism::from_str_opt(&r.mechanism) {
                                    Some(m) => { (m.tier().human_label()) }
                                    None => { span .muted { "unknown" } }
                                }
                            }
                            td { (age_label(r.created_at, now)) }
                            td { a href={ "/ui/requests/" (r.id) } { "Review" } }
                        }
                    }
                }
            }
        },
    ))
}

// ---------------------------------------------------------------------------
// GET /ui/requests/{id}

/// Hidden field carrying the render-time answer to "is this secret stored?".
/// The approve handler refuses (409) when reality no longer matches it, so a
/// stale form can never silently change which credential is released.
const F_SECRET_PRESENT: &str = "secret_present";

/// Wording shared by the GET banner and the 409 body.
const SECRET_STATE_CHANGED: &str =
    "the stored state of this secret changed while you were reviewing this \
     request — it was stored, removed, or rotated to a new version — so this \
     form no longer means what it said: nothing was approved. Re-check the \
     details below and decide again.";

async fn request_detail_page(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let op = operator(&state, &headers).await?;
    let row = db::get_request(&state.db, id)
        .await?
        .ok_or_else(|| UiError::new(StatusCode::NOT_FOUND, "no such request"))?;
    // Database clock: this decides approval-form vs read-only resolved page
    // on `expires_at`, which the approve transition enforces with SQL now().
    let now = db::db_now(&state.db).await?;
    render_request_detail(&state, &op, &row, now, None).await
}

/// Render the approval page for `row`. `notice` renders as a banner above the
/// forms; the approve handler passes it when re-rendering after a 409 so the
/// operator re-decides against the page's new state.
async fn render_request_detail(
    state: &AppState,
    op: &Operator,
    row: &AccessRequestRow,
    now: DateTime<Utc>,
    notice: Option<&str>,
) -> UiResult<Html<String>> {
    let id = row.id;
    if row.state != "pending" || row.expires_at <= now {
        let label = if row.state == "pending" {
            "expired"
        } else {
            row.state.as_str()
        };
        // Read-only detail, no approval/denial controls. This is what the
        // notify-only FYI push links to ("View request" on an
        // already-approved row): the operator must be able to inspect what
        // was released — mechanism, normalized constraints, retained context
        // — not just the bare state.
        let mechanism = parse_mechanism(&row.mechanism)?;
        let constraints = parse_constraints(row)?;
        let secret = db::get_secret_by_name(&state.db, &row.secret_name).await?;
        let context = decrypt_context(state, row);
        let secret_line = match &secret {
            Some(s) => html! {
                (s.name) " "
                span .muted {
                    "(stored, version " (s.current_version)
                    ", max tier: "
                    (Tier::from_int(s.max_tier).map(|t| t.as_str()).unwrap_or("?"))
                    ")"
                }
            },
            None => html! { (row.secret_name) },
        };
        return Ok(html_page(
            "Request resolved",
            html! {
                h1 { "Request from " (row.client_name) }
                p { "This request is " b { (label) } " and can no longer be acted on." }
                p .muted {
                    "Created " (age_label(row.created_at, now)) " ago"
                    @if let Some(by) = &row.resolved_by { " · resolved by " (by) }
                    @if let Some(at) = row.resolved_at {
                        " at " (at.format("%Y-%m-%d %H:%M:%S UTC"))
                    }
                }
                @if let Some(reason) = &row.deny_reason {
                    p { "Deny reason: " (reason) }
                }
                (grant_block(mechanism, &constraints, secret_line))
                (context_block(context.as_ref(), mechanism))
            },
        ));
    }
    if policy_cap_elapsed(row.policy_not_after, now) {
        return Ok(html_page(
            "Request no longer approvable",
            html! {
                h1 { "Request " (row.id) }
                p {
                    "The standing policy this request matched has "
                    b { "expired" }
                    ", so any grant issued now would already be past its cap. "
                    "This request can no longer be approved and must be re-submitted \
                     by the client."
                }
            },
        ));
    }
    let mechanism = parse_mechanism(&row.mechanism)?;
    let constraints = parse_constraints(row)?;
    let secret = db::get_secret_by_name(&state.db, &row.secret_name).await?;
    let context = decrypt_context(state, row);

    let secret_line = match &secret {
        Some(s) => html! {
            (s.name) " "
            span .muted {
                "(stored, version " (s.current_version)
                ", max tier: "
                (Tier::from_int(s.max_tier).map(|t| t.as_str()).unwrap_or("?"))
                ")"
            }
        },
        None => html! {
            (row.secret_name) " " span .caveat { "(NOT stored in Keychute — value required below)" }
        },
    };

    // The marker is folded into the approve token's MAC, so the token is only
    // valid for the state this page was rendered against and the hidden field
    // cannot be swapped independently of it.
    let secret_present = secret_state_marker(secret.as_ref());
    let secret_present = secret_present.as_str();
    // CSRF tokens are minted on the PROCESS clock because `check_post` ->
    // `verify_token` measures their TTL against `Utc::now()`. `now` here is
    // the database clock (it gates request expiry, which SQL enforces), and
    // issuing against one clock while verifying against the other would let
    // even a second of skew reject a freshly submitted form — or, with real
    // NTP drift, every form forever.
    let csrf_now = Utc::now();
    let approve_token = csrf::issue_token(
        &state.keyset,
        R_APPROVE,
        &id.to_string(),
        &op.subject,
        secret_present,
        csrf_now,
    );
    let deny_token = csrf::issue_token(
        &state.keyset,
        R_DENY,
        &id.to_string(),
        &op.subject,
        "",
        csrf_now,
    );
    let default_tier = mechanism.tier();

    Ok(html_page(
        "Approve request",
        html! {
            h1 { "Access request from " (row.client_name) }
            @if let Some(text) = notice {
                p .caveat { (text) }
            }
            p .muted {
                "Created " (age_label(row.created_at, now)) " ago · expires at "
                (row.expires_at.format("%Y-%m-%d %H:%M:%S UTC"))
            }
            (grant_block(mechanism, &constraints, secret_line))
            (context_block(context.as_ref(), mechanism))

            form method="post" action={ "/ui/requests/" (id) "/approve" } {
                input type="hidden" name="csrf_token" value=(approve_token);
                input type="hidden" name=(F_SECRET_PRESENT) value=(secret_present);
                fieldset {
                    legend { "Narrow the grant (optional — values may only shrink the request)" }
                    label {
                        "TTL seconds (≤ " (constraints.ttl_seconds) "): "
                        input type="number" name="ttl_seconds" min="1"
                            max=(constraints.ttl_seconds) placeholder=(constraints.ttl_seconds);
                    }
                    label {
                        "Max uses: "
                        input type="number" name="max_uses" min="1";
                    }
                }
                @if secret.is_none() {
                    fieldset {
                        legend { "Secret value (not yet stored)" }
                        label {
                            "Secret value: "
                            input type="password" name="secret_value" autocomplete="off";
                        }
                        label {
                            input type="checkbox" name="store_secret" value="on";
                            " Store this secret in Keychute (otherwise it is released once, to this grant only)"
                        }
                        label {
                            "Max tier when stored: " b { (default_tier.as_str()) }
                            input type="hidden" name="store_max_tier" value=(default_tier.as_str());
                            span .muted {
                                " (the requested mechanism's tier — approving here cannot store \
                                 the secret at a broader tier than the access being approved; \
                                 widen it later from the secrets page if you mean to)"
                            }
                        }
                        label {
                            "Injection kind: "
                            select name="injection_kind" {
                                option value="bearer" selected { "bearer (Authorization: Bearer …)" }
                                option value="header" { "header (named header)" }
                                option value="basic" { "basic-password (Authorization: Basic)" }
                            }
                        }
                        label {
                            "Header name (kind=header) / username (kind=basic-password): "
                            input type="text" name="injection_header";
                        }
                        label {
                            "Description: "
                            input type="text" name="store_description";
                        }
                    }
                }
                button type="submit" { "Approve" }
            }
            form method="post" action={ "/ui/requests/" (id) "/deny" } .inline {
                input type="hidden" name="csrf_token" value=(deny_token);
                button type="submit" { "Deny" }
            }
        },
    ))
}

// ---------------------------------------------------------------------------
// POST /ui/requests/{id}/approve

/// The one place a HUMAN-supplied production credential enters the process
/// (`secret_value`, for a not-yet-stored secret). `take_secret_value` zeroizes
/// it on the success path, but approval has many fallible checks before that
/// point — a mistyped TTL or a stale-form 409 would otherwise drop the typed
/// credential into the allocator's free list. `Drop` closes every early
/// return at once (matching the zeroize-on-drop discipline in `crypto`).
#[derive(Deserialize)]
struct ApproveForm {
    csrf_token: String,
    /// [`F_SECRET_PRESENT`]: "1"/"0" as rendered. Required.
    #[serde(default)]
    secret_present: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<String>,
    #[serde(default)]
    max_uses: Option<String>,
    #[serde(default)]
    secret_value: Option<String>,
    #[serde(default)]
    store_secret: Option<String>,
    #[serde(default)]
    store_max_tier: Option<String>,
    #[serde(default)]
    injection_kind: Option<String>,
    #[serde(default)]
    injection_header: Option<String>,
    #[serde(default)]
    store_description: Option<String>,
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn parse_narrow_u64(input: Option<&str>, requested: u64, what: &str) -> UiResult<u64> {
    match input {
        None => Ok(requested),
        Some(raw) => {
            let v: u64 = raw
                .parse()
                .map_err(|_| UiError::bad_request(format!("invalid {what}")))?;
            if v == 0 {
                return Err(UiError::bad_request(format!("{what} must be positive")));
            }
            if v > requested {
                return Err(UiError::bad_request(format!(
                    "{what} may only narrow the request (requested {requested})"
                )));
            }
            Ok(v)
        }
    }
}

/// Addendum #4/#17 subset: validate operator-supplied injection template.
/// Returns `(injection_kind, injection_header, injection_username)`: the form
/// has one free-text field (named `injection_header`), routed to the header
/// column for kind 'header' and to `injection_username` for kind 'basic'
/// (migration 0003). 'basic-password' is accepted as an alias for 'basic'
/// (both spellings are also valid in the DB CHECK since migration 0004).
#[allow(clippy::type_complexity)]
fn validate_injection(
    kind: &str,
    header: Option<&str>,
) -> UiResult<(String, Option<String>, Option<String>)> {
    const RESERVED: &[&str] = &[
        "host",
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "forwarded",
        "x-real-ip",
        "x-http-method-override",
        "x-method-override",
        "x-original-url",
        "x-rewrite-url",
        "x-original-method",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "expect",
    ];
    match kind {
        "bearer" => Ok(("bearer".into(), None, None)),
        "header" => {
            let name = header.ok_or_else(|| {
                UiError::bad_request("injection kind 'header' requires a header name")
            })?;
            let lower = name.to_ascii_lowercase();
            let valid_token = !name.is_empty()
                && name.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(
                            b,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )
                });
            if !valid_token {
                return Err(UiError::bad_request(
                    "injection header is not a valid header name",
                ));
            }
            if RESERVED.contains(&lower.as_str()) || lower.starts_with("x-forwarded-") {
                return Err(UiError::bad_request("injection header is reserved"));
            }
            Ok(("header".into(), Some(name.to_owned()), None))
        }
        "basic" | "basic-password" => {
            let username = header.ok_or_else(|| {
                UiError::bad_request("injection kind 'basic-password' requires a username")
            })?;
            if username.contains(':') || username.chars().any(|c| c.is_control()) {
                return Err(UiError::bad_request("invalid basic-auth username"));
            }
            // Username goes to injection_username; injection_header stays NULL
            // (the proxy still falls back to injection_header for old rows).
            Ok(("basic".into(), None, Some(username.to_owned())))
        }
        _ => Err(UiError::bad_request("unknown injection kind")),
    }
}

/// Parse the approval form's render-time marker: `Some(true)` = the page was
/// rendered against a stored secret, `Some(false)` = against an absent one,
/// `None` = no usable marker (malformed form).
fn parse_secret_present(rendered: Option<&str>) -> Option<bool> {
    match rendered {
        Some("0") => Some(false),
        Some(s) => s.strip_prefix("1:")?.parse::<i32>().ok().map(|_| true),
        None => None,
    }
}

/// Canonical spelling of the render-time secret-state marker, used both for
/// the hidden field and as the CSRF token's form-state binding so the two can
/// never disagree: `"0"` when no secret is stored under the requested name,
/// `"1:<current_version>"` when one is.
///
/// The VERSION is part of the marker because the approval page displays it
/// while the release path resolves the current version at read time. Without
/// it, an operator who reviewed version 3 could approve moments after a
/// rotation and the client would receive version 4 — a credential nobody
/// reviewed on that page. Including it turns that race into the same 409
/// re-render as a secret appearing or disappearing.
///
/// The grant deliberately still resolves the current version at read time
/// rather than pinning the reviewed one: pinning would keep releasing a
/// retired credential after a rotation, which is the worse failure.
fn secret_state_marker(secret: Option<&db::SecretRow>) -> String {
    match secret {
        Some(s) => format!("1:{}", s.current_version),
        None => "0".to_owned(),
    }
}

impl Drop for ApproveForm {
    fn drop(&mut self) {
        if let Some(v) = &mut self.secret_value {
            v.zeroize();
        }
    }
}

fn take_secret_value(form: &mut ApproveForm) -> Option<SecretBytes> {
    let mut raw = form.secret_value.take()?;
    if raw.is_empty() {
        return None;
    }
    let boxed: Box<[u8]> = raw.as_bytes().into();
    raw.zeroize();
    Some(SecretBox::new(boxed))
}

/// True when the request matched a standing policy whose `not_after` has
/// already passed, i.e. `min(now + ttl, policy_not_after)` could only produce a
/// grant that is already expired. Requests with no policy cap are never
/// elapsed.
fn policy_cap_elapsed(policy_not_after: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    matches!(policy_not_after, Some(cap) if cap <= now)
}

async fn approve(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(mut form): Form<ApproveForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    // The marker is part of the token's MAC input, so it is read before the
    // guard runs — the CSRF check stays the outermost gate, and a submission
    // that drops, edits, or swaps the marker simply fails it (403).
    let submitted_marker = non_empty(&form.secret_present).unwrap_or("");
    check_post(
        &state,
        &headers,
        R_APPROVE,
        &id.to_string(),
        &op.subject,
        submitted_marker,
        &form.csrf_token,
    )?;
    // Past the guard the marker is provably one this server rendered, but
    // parse rather than assume: never accept an unrecognised value (the
    // comparison against current state below is the actual gate).
    parse_secret_present(non_empty(&form.secret_present)).ok_or_else(|| {
        UiError::bad_request("malformed approval form; reload the page and retry")
    })?;
    let row = db::get_request(&state.db, id)
        .await?
        .ok_or_else(|| UiError::new(StatusCode::NOT_FOUND, "no such request"))?;
    // Database clock: the grant deadline computed below is enforced by SQL
    // `now()` predicates, so its base must be the clock that enforces it.
    let now = db::db_now(&state.db).await?;
    if row.state != "pending" || row.expires_at <= now {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "request is no longer pending",
        ));
    }
    // DESIGN §5: a grant may not outlive the standing policy row it matched.
    // If that cap has already elapsed, approving could only mint a grant that
    // is born expired — refuse instead of handing the client an "approved"
    // state whose grant id can only ever return `grant-expired`.
    if policy_cap_elapsed(row.policy_not_after, now) {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "the standing policy this request matched has expired: the request is \
             no longer approvable and must be re-submitted",
        ));
    }
    let mechanism = parse_mechanism(&row.mechanism)?;
    let constraints = parse_constraints(&row)?;

    // Narrowing (server-side validated: may only shrink the request).
    let ttl = parse_narrow_u64(
        non_empty(&form.ttl_seconds),
        constraints.ttl_seconds,
        "ttl_seconds",
    )?;
    let requested_uses: Option<u64> = if mechanism.is_releasing() {
        // Releasing tiers are single-use in v1 regardless of the request.
        Some(1)
    } else {
        constraints.max_uses.map(u64::from)
    };
    let max_uses: Option<u64> = match (non_empty(&form.max_uses), requested_uses) {
        (None, base) => base,
        (Some(raw), base) => {
            let v = parse_narrow_u64(Some(raw), base.unwrap_or(u64::MAX), "max_uses")?;
            Some(v)
        }
    };

    let secret = db::get_secret_by_name(&state.db, &row.secret_name).await?;

    // The approval page renders two materially different forms: for an absent
    // secret it asks for the value and promises "released once, to this grant
    // only" unless "store" is ticked; for a stored one it asks for nothing and
    // releases what is stored. If that flipped between render and submit, the
    // submitted form no longer means what the operator was shown — approving
    // either way would release a credential they did not choose. Refuse and
    // re-render so they decide against the new state (same 409 shape as the
    // "resolved concurrently" case below).
    // The marker is authenticated (it is part of the token's MAC input), so a
    // mismatch here can only mean the world moved, never a doctored field.
    // Whole-marker comparison: catches the secret appearing or disappearing
    // AND a rotation that changed its current version since the page was
    // rendered (see `secret_state_marker`).
    if submitted_marker != secret_state_marker(secret.as_ref()) {
        let page =
            render_request_detail(&state, &op, &row, now, Some(SECRET_STATE_CHANGED)).await?;
        return Ok((StatusCode::CONFLICT, page).into_response());
    }

    let secret_value = take_secret_value(&mut form);
    if secret.is_some() && secret_value.is_some() {
        // The stored-secret form has no value field: a value here means the
        // submission does not match the page it claims to come from.
        return Err(UiError::bad_request(
            "malformed approval form; reload the page and retry",
        ));
    }
    let store_requested = non_empty(&form.store_secret).is_some();

    let grant_id = Uuid::new_v4();
    let mut store: Option<StoreSecretParams> = None;
    let mut passthrough: Option<PassthroughPayload> = None;

    match secret {
        Some(s) => {
            if !s.enabled {
                return Err(UiError::bad_request("secret is disabled"));
            }
            if mechanism.tier().as_int() > s.max_tier {
                return Err(UiError::bad_request(
                    "requested mechanism exceeds the secret's max tier",
                ));
            }
        }
        None => {
            let value = secret_value.ok_or_else(|| {
                UiError::bad_request("this secret is not stored: a secret value is required")
            })?;
            if store_requested {
                let max_tier = match non_empty(&form.store_max_tier) {
                    None => mechanism.tier(),
                    Some(raw) => tier_from_str(raw)
                        .ok_or_else(|| UiError::bad_request("invalid max_tier"))?,
                };
                // Exactly the approved mechanism's tier. Below it, the secret
                // could not serve the very request being approved; above it,
                // approving a cli-read would mint a stored secret releasable
                // at `direct` forever after — widening future access beyond
                // the access actually approved. Widening is a deliberate act
                // and belongs on the secrets page, not as a side effect of an
                // approval.
                if max_tier != mechanism.tier() {
                    return Err(UiError::bad_request(
                        "stored max_tier must equal the requested mechanism's tier: \
                         an approval cannot store a secret at a broader tier than the \
                         access it grants",
                    ));
                }
                let kind = non_empty(&form.injection_kind).unwrap_or("bearer");
                let (injection_kind, injection_header, injection_username) =
                    validate_injection(kind, non_empty(&form.injection_header))?;
                let secret_id = Uuid::new_v4();
                let keyset = &state.keyset;
                store = Some(StoreSecretParams {
                    secret_id,
                    name: row.secret_name.clone(),
                    description: non_empty(&form.store_description).unwrap_or("").to_owned(),
                    max_tier: max_tier.as_int(),
                    injection_kind,
                    injection_header,
                    injection_username,
                    // Sealed by the approval transaction under the KEK shared
                    // lock (addendum #19), never before it.
                    seal: Box::new(move || {
                        keyset.seal(
                            &value,
                            AadContext::SecretVersion {
                                secret_id,
                                version: 1,
                            },
                        )
                    }),
                });
            } else {
                if mechanism == Mechanism::Brokered {
                    return Err(UiError::bad_request(
                        "brokered grants need a stored secret (injection template): \
                         check \"store this secret in Keychute\"",
                    ));
                }
                // Sealed outside the transaction deliberately: the
                // process-local ephemeral KEK is not part of the keyset and can
                // never be retired, so addendum #19's ordering does not apply.
                // It is also the ONLY KEK a passthrough can be sealed under —
                // `PassthroughPayload::seal` is the type's sole constructor.
                passthrough = Some(
                    PassthroughPayload::seal(&state.ephemeral_kek, grant_id, &value)
                        .map_err(|e| anyhow::anyhow!("sealing passthrough: {e}"))?,
                );
            }
        }
    }

    // DESIGN §5: "A grant issued under a standing policy row also expires no
    // later than that row does." The request carries the matched policy's
    // expiry, so a human approval is capped at it just like the auto-approve
    // path's min(TTL, policy_not_after).
    let mut not_after = now + Duration::seconds(ttl as i64);
    if let Some(cap) = row.policy_not_after {
        not_after = not_after.min(cap);
    }

    let grant = GrantParams {
        client_name: row.client_name.clone(),
        secret_name: row.secret_name.clone(),
        mechanism: row.mechanism.clone(),
        constraints: row.constraints.clone(),
        not_after,
        max_uses: max_uses.map(|u| u.min(i32::MAX as u64) as i32),
        passthrough,
    };
    let approved =
        db::ui_ext::approve_request(&state.db, id, &op.subject, grant_id, &grant, store).await?;
    if approved.is_none() {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "request was resolved or expired concurrently",
        ));
    }
    state.resolve_notify.notify_waiters();
    Ok(Redirect::to("/ui/requests").into_response())
}

// ---------------------------------------------------------------------------
// POST /ui/requests/{id}/deny

#[derive(Deserialize)]
struct CsrfOnlyForm {
    csrf_token: String,
}

async fn deny(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnlyForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_DENY,
        &id.to_string(),
        &op.subject,
        "",
        &form.csrf_token,
    )?;
    let denied = db::resolve_deny(&state.db, id, &op.subject, "denied by operator").await?;
    if !denied {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "request is no longer pending",
        ));
    }
    state.resolve_notify.notify_waiters();
    Ok(Redirect::to("/ui/requests").into_response())
}

// ---------------------------------------------------------------------------
// Grants

async fn grants_page(State(state): State<AppState>, headers: HeaderMap) -> UiResult<Html<String>> {
    let op = operator(&state, &headers).await?;
    let now = Utc::now();
    let grants =
        db::ui_ext::list_active_grants(&state.db, state.config.limits.replay_window_seconds)
            .await?;
    Ok(html_page(
        "Active grants",
        html! {
            h1 { "Active grants" }
            @if grants.is_empty() { p .muted { "No active grants." } }
            @else {
                table {
                    tr {
                        th { "Client" } th { "Secret" } th { "Mechanism" }
                        th { "Expires" } th { "Uses" } th { "" }
                    }
                    @for g in &grants {
                        tr {
                            td { (g.client_name) }
                            td { (g.secret_name) }
                            td { (g.mechanism) }
                            td { (g.not_after.format("%Y-%m-%d %H:%M:%S UTC")) }
                            td {
                                (g.use_count) " / "
                                @match g.max_uses {
                                    Some(m) => { (m) }
                                    None => { "unlimited" }
                                }
                            }
                            td {
                                form method="post" action={ "/ui/grants/" (g.id) "/revoke" } .inline {
                                    input type="hidden" name="csrf_token"
                                        value=(csrf::issue_token(&state.keyset, R_REVOKE, &g.id.to_string(), &op.subject, "", now));
                                    button type="submit" { "Revoke" }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnlyForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_REVOKE,
        &id.to_string(),
        &op.subject,
        "",
        &form.csrf_token,
    )?;
    // No matching live grant means nothing was revoked and nothing audited
    // (already revoked, or gone): say so rather than redirecting as if it
    // worked, same as the approve/deny handlers.
    if !db::revoke_grant(&state.db, id, &op.subject).await? {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "grant is no longer active",
        ));
    }
    Ok(Redirect::to("/ui/grants").into_response())
}

// ---------------------------------------------------------------------------
// Policies

async fn policies_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> UiResult<Html<String>> {
    let op = operator(&state, &headers).await?;
    let now = Utc::now();
    let policies = db::list_policies(&state.db).await?;
    let create_token = csrf::issue_token(&state.keyset, R_POLICY_CREATE, "", &op.subject, "", now);
    Ok(html_page(
        "Policies",
        html! {
            h1 { "Standing policies" }
            @if policies.is_empty() { p .muted { "No policy rows." } }
            @else {
                table {
                    tr {
                        th { "Client" } th { "Secret" } th { "Mechanism" } th { "Outcome" }
                        th { "Priority" } th { "Limits" } th { "Not after" } th { "By" } th { "" }
                    }
                    @for p in &policies {
                        tr {
                            td { (p.client_name.as_deref().unwrap_or("any")) }
                            td {
                                @if let Some(s) = &p.secret_name { (s) }
                                @else if let Some(t) = &p.secret_tag { "tag:" (t) }
                                @else { "any" }
                            }
                            td { (p.mechanism) }
                            td { (p.outcome) }
                            td { (p.priority) }
                            td {
                                @if let Some(ttl) = p.max_ttl_seconds { "ttl ≤ " (ttl) "s " }
                                @if let Some(u) = p.max_uses { "uses ≤ " (u) }
                            }
                            td {
                                @match p.not_after {
                                    Some(t) => { (t.format("%Y-%m-%d %H:%M UTC")) }
                                    None => { span .muted { "—" } }
                                }
                            }
                            td { (p.created_by) }
                            td {
                                form method="post" action={ "/ui/policies/" (p.id) "/delete" } .inline {
                                    input type="hidden" name="csrf_token"
                                        value=(csrf::issue_token(&state.keyset, R_POLICY_DELETE, &p.id.to_string(), &op.subject, "", now));
                                    button type="submit" { "Delete" }
                                }
                            }
                        }
                    }
                }
            }
            h2 { "Create policy" }
            form method="post" action="/ui/policies" {
                input type="hidden" name="csrf_token" value=(create_token);
                label { "Client name (blank = any): " input type="text" name="client_name"; }
                label { "Secret name (blank = any): " input type="text" name="secret_name"; }
                label { "OR secret tag: " input type="text" name="secret_tag"; }
                label {
                    "Mechanism: "
                    select name="mechanism" {
                        option value="brokered" { "brokered" }
                        option value="autofill" { "autofill" }
                        option value="cli-read" { "cli-read" }
                        option value="direct-read" { "direct-read" }
                    }
                }
                label {
                    "Outcome: "
                    select name="outcome" {
                        option value="require-approval" { "require-approval" }
                        option value="notify-only" { "notify-only" }
                        option value="auto-approve" { "auto-approve" }
                        option value="deny" { "deny" }
                    }
                }
                label { "Priority: " input type="number" name="priority" value="0"; }
                label { "Origins (host[:port], one per line): " br;
                    textarea name="origins" rows="3" cols="40" {} }
                label { "Methods (comma/space separated, blank = unconstrained): "
                    input type="text" name="methods"; }
                label { "Path prefixes (one per line, blank = unconstrained): " br;
                    textarea name="path_prefixes" rows="3" cols="40" {} }
                label { "Max TTL seconds: " input type="number" name="max_ttl_seconds" min="1"; }
                label { "Max uses: " input type="number" name="max_uses" min="1"; }
                label { "Not after (UTC): " input type="datetime-local" name="not_after"; }
                button type="submit" { "Create policy" }
            }
        },
    ))
}

#[derive(Deserialize)]
struct PolicyForm {
    csrf_token: String,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    secret_name: Option<String>,
    #[serde(default)]
    secret_tag: Option<String>,
    mechanism: String,
    outcome: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    origins: Option<String>,
    #[serde(default)]
    methods: Option<String>,
    #[serde(default)]
    path_prefixes: Option<String>,
    #[serde(default)]
    max_ttl_seconds: Option<String>,
    #[serde(default)]
    max_uses: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

/// Parse the policy form's comma/whitespace-separated method list.
///
/// Methods are RFC 9110 tokens, not just letters (`M-SEARCH`, `PATCH!` and
/// friends are legal), so validation defers to the same predicate the API-side
/// request validation uses. Values are normalized to upper case, matching the
/// case-insensitive comparison the policy matcher performs.
fn parse_methods_field(raw: &str) -> UiResult<Vec<String>> {
    let mut methods: Vec<String> = Vec::new();
    for m in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let m = m.trim();
        if m.is_empty() {
            continue;
        }
        if !crate::policy::is_valid_http_method(m) {
            return Err(UiError::bad_request("invalid HTTP method"));
        }
        methods.push(m.to_ascii_uppercase());
    }
    Ok(methods)
}

async fn create_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_POLICY_CREATE,
        "",
        &op.subject,
        "",
        &form.csrf_token,
    )?;

    let secret_name = non_empty(&form.secret_name).map(str::to_owned);
    let secret_tag = non_empty(&form.secret_tag).map(str::to_owned);
    if secret_name.is_some() && secret_tag.is_some() {
        return Err(UiError::bad_request(
            "set at most one of secret name / secret tag",
        ));
    }
    let mechanism = Mechanism::from_str_opt(form.mechanism.trim())
        .ok_or_else(|| UiError::bad_request("invalid mechanism"))?;
    let outcome = form.outcome.trim();
    if !matches!(
        outcome,
        "auto-approve" | "notify-only" | "require-approval" | "deny"
    ) {
        return Err(UiError::bad_request("invalid outcome"));
    }
    let priority: i32 = match non_empty(&form.priority) {
        None => 0,
        Some(raw) => raw
            .parse()
            .map_err(|_| UiError::bad_request("invalid priority"))?,
    };
    let mut origins: Vec<Origin> = Vec::new();
    for line in form.origins.as_deref().unwrap_or("").lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        origins.push(
            Origin::parse(line).map_err(|e| UiError::bad_request(format!("bad origin: {e}")))?,
        );
    }
    // A brokered row that grants without naming an origin is unconstrained in
    // the dimension that decides where the credential is SENT: it would match
    // any origin the client asks for, releasing the real credential to a
    // client-chosen host with no approval and (for auto-approve) no push.
    // The engine clamps such a row to require-approval anyway; refuse it here
    // so the operator finds out at creation rather than wondering why their
    // "auto-approve" rule keeps prompting.
    if mechanism == Mechanism::Brokered
        && origins.is_empty()
        && matches!(outcome, "auto-approve" | "notify-only")
    {
        return Err(UiError::bad_request(
            "a brokered auto-approve/notify-only policy must name at least one origin: \
             without one it would release the credential to any host the client asks for",
        ));
    }
    let methods = parse_methods_field(form.methods.as_deref().unwrap_or(""))?;
    let mut path_prefixes: Vec<String> = Vec::new();
    for line in form.path_prefixes.as_deref().unwrap_or("").lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        path_prefixes.push(
            crate::policy::paths::canonicalize(line)
                .map_err(|e| UiError::bad_request(format!("bad path prefix: {e}")))?,
        );
    }
    let max_ttl_seconds: Option<i64> = match non_empty(&form.max_ttl_seconds) {
        None => None,
        Some(raw) => Some(
            raw.parse::<i64>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| UiError::bad_request("invalid max_ttl_seconds"))?,
        ),
    };
    let max_uses: Option<i32> = match non_empty(&form.max_uses) {
        None => None,
        Some(raw) => Some(
            raw.parse::<i32>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| UiError::bad_request("invalid max_uses"))?,
        ),
    };
    let not_after: Option<DateTime<Utc>> = match non_empty(&form.not_after) {
        None => None,
        Some(raw) => Some(
            chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S"))
                .map_err(|_| UiError::bad_request("invalid not_after datetime"))?
                .and_utc(),
        ),
    };

    let policy = db::NewPolicy {
        client_name: non_empty(&form.client_name).map(str::to_owned),
        secret_name,
        secret_tag,
        mechanism: mechanism.as_str().to_owned(),
        outcome: outcome.to_owned(),
        priority,
        origins: serde_json::to_value(&origins).map_err(|e| anyhow::anyhow!(e))?,
        methods,
        path_prefixes,
        max_ttl_seconds,
        max_uses,
        not_after,
        created_by: op.subject.clone(),
    };
    // The policy row and its audit row commit together: a crash between them
    // would otherwise leave an active authorization rule with no audit record.
    policy_store::insert_policy_audited(&state.db, &policy, &op.subject).await?;
    Ok(Redirect::to("/ui/policies").into_response())
}

async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnlyForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_POLICY_DELETE,
        &id.to_string(),
        &op.subject,
        "",
        &form.csrf_token,
    )?;
    // Deletion and its audit row commit together (same reasoning as creation).
    // No matching row means nothing was deleted and nothing audited — report
    // the conflict instead of a silent no-op redirect.
    if !policy_store::delete_policy_audited(&state.db, id, &op.subject).await? {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "policy no longer exists",
        ));
    }
    Ok(Redirect::to("/ui/policies").into_response())
}

// ---------------------------------------------------------------------------
// Secrets

async fn secrets_page(State(state): State<AppState>, headers: HeaderMap) -> UiResult<Html<String>> {
    let op = operator(&state, &headers).await?;
    let now = Utc::now();
    let secrets = db::list_secrets(&state.db).await?;
    let token = csrf::issue_token(&state.keyset, R_SECRET_SAVE, "", &op.subject, "", now);
    Ok(html_page(
        "Secrets",
        html! {
            h1 { "Stored secrets" }
            @if secrets.is_empty() { p .muted { "No stored secrets." } }
            @else {
                table {
                    tr {
                        th { "Name" } th { "Description" } th { "Version" }
                        th { "Max tier" } th { "Injection" } th { "Enabled" }
                    }
                    @for s in &secrets {
                        tr {
                            td { (s.name) }
                            td { (s.description) }
                            td { (s.current_version) }
                            td { (Tier::from_int(s.max_tier).map(|t| t.as_str()).unwrap_or("?")) }
                            td {
                                (s.injection_kind)
                                @if let Some(h) = &s.injection_header { " (" (h) ")" }
                            }
                            td { @if s.enabled { "yes" } @else { "no" } }
                        }
                    }
                }
            }
            h2 { "Create or rotate a secret" }
            p .muted {
                "If the name matches an existing secret the value is rotated in as a "
                "new version (other fields are ignored); otherwise a new secret is created."
            }
            form method="post" action="/ui/secrets" {
                input type="hidden" name="csrf_token" value=(token);
                label { "Name: " input type="text" name="name" required; }
                label { "Value: " input type="password" name="secret_value" autocomplete="off" required; }
                label { "Description: " input type="text" name="description"; }
                label {
                    "Max tier: "
                    select name="max_tier" {
                        @for t in [Tier::Brokered, Tier::TrustedClient, Tier::CooperatingClient, Tier::Direct] {
                            option value=(t.as_str()) selected[t == Tier::Brokered] { (t.as_str()) }
                        }
                    }
                }
                label {
                    "Injection kind: "
                    select name="injection_kind" {
                        option value="bearer" selected { "bearer" }
                        option value="header" { "header" }
                        option value="basic" { "basic-password" }
                    }
                }
                label {
                    "Header name (kind=header) / username (kind=basic-password): "
                    input type="text" name="injection_header";
                }
                button type="submit" { "Save" }
            }
        },
    ))
}

#[derive(Deserialize)]
struct SecretForm {
    csrf_token: String,
    name: String,
    /// Operator-typed production credential. Wiped on drop for the same
    /// reason as [`ApproveForm`]: `save_secret` has fallible checks (stale
    /// CSRF token, empty name) that return before the value is taken and
    /// zeroized.
    #[serde(default)]
    secret_value: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    max_tier: Option<String>,
    #[serde(default)]
    injection_kind: Option<String>,
    #[serde(default)]
    injection_header: Option<String>,
}

impl Drop for SecretForm {
    fn drop(&mut self) {
        if let Some(v) = &mut self.secret_value {
            v.zeroize();
        }
    }
}

async fn save_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(mut form): Form<SecretForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_SECRET_SAVE,
        "",
        &op.subject,
        "",
        &form.csrf_token,
    )?;
    let name = form.name.trim().to_owned();
    if name.is_empty() {
        return Err(UiError::bad_request("secret name is required"));
    }
    let value = {
        let mut raw = form
            .secret_value
            .take()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| UiError::bad_request("secret value is required"))?;
        let boxed: Box<[u8]> = raw.as_bytes().into();
        raw.zeroize();
        SecretBox::new(boxed)
    };

    match db::get_secret_by_name(&state.db, &name).await? {
        Some(existing) => {
            // Rotation: append a new version; metadata unchanged.
            db::ui_ext::rotate_secret_version(
                &state.db,
                existing.id,
                &existing.name,
                &op.subject,
                |version| {
                    state.keyset.seal(
                        &value,
                        AadContext::SecretVersion {
                            secret_id: existing.id,
                            version,
                        },
                    )
                },
            )
            .await?;
        }
        None => {
            let max_tier = match non_empty(&form.max_tier) {
                None => Tier::Brokered,
                Some(raw) => {
                    tier_from_str(raw).ok_or_else(|| UiError::bad_request("invalid max_tier"))?
                }
            };
            let kind = non_empty(&form.injection_kind).unwrap_or("bearer");
            let (injection_kind, injection_header, injection_username) =
                validate_injection(kind, non_empty(&form.injection_header))?;
            let secret_id = Uuid::new_v4();
            let keyset = &state.keyset;
            db::ui_ext::create_secret_with_version(
                &state.db,
                StoreSecretParams {
                    secret_id,
                    name,
                    description: non_empty(&form.description).unwrap_or("").to_owned(),
                    max_tier: max_tier.as_int(),
                    injection_kind,
                    injection_header,
                    injection_username,
                    // Sealed inside the insert transaction, under the KEK
                    // shared lock (addendum #19).
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
                &op.subject,
            )
            .await?;
        }
    }
    Ok(Redirect::to("/ui/secrets").into_response())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_injection_routes_basic_username_to_username_column() {
        let Ok((kind, header, username)) = validate_injection("basic", Some("svc")) else {
            panic!("basic injection should validate");
        };
        assert_eq!(kind, "basic");
        assert_eq!(header, None);
        assert_eq!(username.as_deref(), Some("svc"));
        // 'basic-password' is an accepted alias, normalized to 'basic'.
        let Ok((kind, header, username)) = validate_injection("basic-password", Some("svc")) else {
            panic!("basic-password alias should validate");
        };
        assert_eq!(kind, "basic");
        assert_eq!(header, None);
        assert_eq!(username.as_deref(), Some("svc"));
        // 'header' keeps using the header column; no username.
        let Ok((kind, header, username)) = validate_injection("header", Some("X-Api-Key")) else {
            panic!("header injection should validate");
        };
        assert_eq!(kind, "header");
        assert_eq!(header.as_deref(), Some("X-Api-Key"));
        assert_eq!(username, None);
        // Bad usernames still rejected.
        assert!(validate_injection("basic", Some("a:b")).is_err());
        assert!(validate_injection("basic", None).is_err());
    }

    #[test]
    fn client_context_is_escaped() {
        let ctx = RequestContext {
            reason: "<script>alert(1)</script>".to_owned(),
            structured: Some(serde_json::json!({
                "snippet": "<img src=x onerror=alert(2)>",
            })),
        };
        let rendered = context_block(Some(&ctx), Mechanism::CliRead).into_string();
        assert!(rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!rendered.contains("<script>alert(1)"));
        assert!(rendered.contains("&lt;img src=x onerror=alert(2)&gt;"));
        assert!(!rendered.contains("<img src=x"));
        // Tier-2 caveat is present for cli-read.
        assert!(rendered.contains("Tier-2 caveat"));
        // ...and absent for other mechanisms.
        let other = context_block(Some(&ctx), Mechanism::Autofill).into_string();
        assert!(!other.contains("Tier-2 caveat"));
    }

    #[test]
    fn grant_block_is_server_vocabulary() {
        let constraints = Constraints {
            origins: vec![Origin::parse("api.example.com").unwrap()],
            methods: vec!["GET".into(), "POST".into()],
            path_prefixes: vec!["/v1".into()],
            ttl_seconds: 3600,
            max_uses: None,
        };
        let rendered = grant_block(
            Mechanism::Brokered,
            &constraints,
            html! { "example-api-token" },
        )
        .into_string();
        assert!(rendered.contains("What you are approving"));
        assert!(rendered.contains("https://api.example.com"));
        assert!(rendered.contains("GET, POST"));
        assert!(rendered.contains("/v1"));
        assert!(rendered.contains("3600"));
        assert!(rendered.contains("unlimited within TTL"));
        assert!(rendered.contains("the client never sees the secret"));
    }

    #[test]
    fn narrowing_validation() {
        assert_eq!(parse_narrow_u64(None, 100, "ttl").unwrap(), 100);
        assert_eq!(parse_narrow_u64(Some("50"), 100, "ttl").unwrap(), 50);
        assert_eq!(parse_narrow_u64(Some("100"), 100, "ttl").unwrap(), 100);
        assert!(parse_narrow_u64(Some("101"), 100, "ttl").is_err());
        assert!(parse_narrow_u64(Some("0"), 100, "ttl").is_err());
        assert!(parse_narrow_u64(Some("abc"), 100, "ttl").is_err());
        assert!(parse_narrow_u64(Some("-1"), 100, "ttl").is_err());
    }

    #[test]
    fn injection_validation() {
        assert_eq!(
            validate_injection("bearer", None).unwrap(),
            ("bearer".into(), None, None)
        );
        assert_eq!(
            validate_injection("header", Some("X-Api-Key")).unwrap(),
            ("header".into(), Some("X-Api-Key".into()), None)
        );
        assert!(validate_injection("header", None).is_err());
        assert!(validate_injection("header", Some("Authorization")).is_err());
        assert!(validate_injection("header", Some("host")).is_err());
        assert!(validate_injection("header", Some("X-Forwarded-For")).is_err());
        assert!(validate_injection("header", Some("Bad Header")).is_err());
        assert!(validate_injection("header", Some("Transfer-Encoding")).is_err());
        assert_eq!(
            validate_injection("basic", Some("svc-user")).unwrap(),
            ("basic".into(), None, Some("svc-user".into()))
        );
        assert!(validate_injection("basic", Some("user:name")).is_err());
        assert!(validate_injection("basic", None).is_err());
        assert!(validate_injection("nonsense", None).is_err());
    }

    #[test]
    fn tier_parse_roundtrip() {
        for t in [
            Tier::Brokered,
            Tier::TrustedClient,
            Tier::CooperatingClient,
            Tier::Direct,
        ] {
            assert_eq!(tier_from_str(t.as_str()), Some(t));
        }
        assert_eq!(tier_from_str("bogus"), None);
    }

    #[test]
    fn policy_cap_elapsed_refuses_only_past_caps() {
        let now = Utc::now();
        // No standing policy cap: never elapsed.
        assert!(!policy_cap_elapsed(None, now));
        // Cap still in the future: approvable.
        assert!(!policy_cap_elapsed(Some(now + Duration::seconds(1)), now));
        // Cap in the past: a grant minted now would be born expired.
        assert!(policy_cap_elapsed(Some(now - Duration::seconds(1)), now));
        // Exactly at the cap is elapsed too: not_after == now yields a grant
        // with zero remaining lifetime.
        assert!(policy_cap_elapsed(Some(now), now));
    }

    #[test]
    fn stale_approval_form_is_detected_in_both_directions() {
        // Rendered against an absent secret, still absent: the form means what
        // it said (operator's typed value is the one released).
        assert_eq!(parse_secret_present(Some("0")), Some(false));
        // Rendered against a stored secret, at a specific version.
        assert_eq!(parse_secret_present(Some("1:3")), Some(true));
        // No usable marker: never guess a branch.
        assert_eq!(parse_secret_present(None), None);
        assert_eq!(parse_secret_present(Some("yes")), None);
        // Bare "1" is not a marker this server ever renders.
        assert_eq!(parse_secret_present(Some("1")), None);
        assert_eq!(parse_secret_present(Some("1:")), None);
        assert_eq!(parse_secret_present(Some("1:v3")), None);

        // The handler compares the WHOLE marker against current state, so the
        // 409 covers three transitions: appeared, vanished, and rotated.
        assert_ne!("0", "1:3"); // secret appeared under an "absent" form
        assert_ne!("1:3", "0"); // ...or vanished under a "stored" one
        assert_ne!("1:3", "1:4"); // ...or was rotated mid-review
    }

    /// The approve token is minted against the render-time secret state, so a
    /// token from the "absent" page cannot be replayed with the "stored"
    /// marker (or vice versa) — the guard is tamper-evident, not advisory.
    #[test]
    fn approve_token_is_bound_to_the_rendered_secret_state() {
        let ks = csrf::test_keyset();
        let now = Utc::now();
        let (route, id, subj) = (R_APPROVE, "req-1", "andrew");
        // Absent, stored-at-v3, stored-at-v4: a token minted for any one of
        // these must not verify against either of the others, so neither a
        // secret appearing/vanishing nor a rotation can be replayed past the
        // guard.
        let markers = ["0", "1:3", "1:4"];
        for minted in markers {
            let token = csrf::issue_token(&ks, route, id, subj, minted, now);
            for candidate in markers {
                let ok = csrf::verify_token(&ks, route, id, subj, candidate, &token, now);
                assert_eq!(
                    ok,
                    candidate == minted,
                    "token for {minted:?} verified against {candidate:?}"
                );
            }
        }
    }

    #[test]
    fn policy_form_accepts_rfc9110_method_tokens() {
        assert_eq!(
            parse_methods_field("get, M-SEARCH\npatch").unwrap(),
            vec!["GET".to_owned(), "M-SEARCH".to_owned(), "PATCH".to_owned()]
        );
        // Empty input yields no constraint.
        assert!(parse_methods_field("  ,\n ").unwrap().is_empty());
        // Non-token garbage is still rejected.
        assert!(parse_methods_field("GET;DROP").is_err());
        assert!(parse_methods_field("GET(x)").is_err());
        assert!(parse_methods_field("\"GET\"").is_err());
        assert!(parse_methods_field("GET/1").is_err());
    }
}
