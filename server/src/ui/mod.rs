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

use base64::Engine as _;

use crate::audit;
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
const R_SECRET_REVEAL: &str = "/ui/secrets/reveal";
const R_SECRET_VET: &str = "/ui/secrets/vet";

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
        .route("/ui/secrets/{id}/review", post(review_secret))
        .route("/ui/secrets/{id}/reviewed", post(mark_reviewed))
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
                (page_head("Something went wrong", html! { "The action was not carried out." }))
                div .callout .callout-danger {
                    p { (self.msg) }
                }
                p { a .btn-link href="/ui/requests" { "← Back to pending requests" } }
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

/// Stylesheet for every UI page.
///
/// Inlined deliberately: the CSP is `default-src 'none'; style-src
/// 'unsafe-inline'`, so there is no stylesheet to fetch and no script at all.
/// Everything responsive here is therefore pure CSS — nav wraps rather than
/// collapsing behind a JS toggle, and wide tables restyle into stacked cards
/// via `data-label` rather than being scrolled by a script.
const STYLE: &str = r#"
*, *::before, *::after { box-sizing: border-box; }

:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --bg-accent: #eef1f6;
  --surface: #ffffff;
  --surface-2: #f3f5f8;
  --border: #dde1e7;
  --border-strong: #c3cad3;
  --text: #14181f;
  --text-muted: #59626f;
  --accent: #3a54c9;
  --accent-hover: #2f45a8;
  --accent-soft: #eaeeff;
  --on-accent: #ffffff;
  --ok: #17784a;
  --ok-bg: #eaf7f0;
  --ok-border: #a9ddc2;
  --warn: #8f5108;
  --warn-bg: #fdf4e6;
  --warn-border: #ecc98f;
  --danger: #b32626;
  --danger-bg: #fdeded;
  --danger-border: #eeb3b3;
  --radius: 14px;
  --radius-sm: 9px;
  --shadow: 0 1px 2px rgba(16, 24, 40, .05), 0 4px 14px rgba(16, 24, 40, .05);
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1116;
    --bg-accent: #141922;
    --surface: #171c25;
    --surface-2: #1e2530;
    --border: #2a323f;
    --border-strong: #3a4553;
    --text: #e7ebf1;
    --text-muted: #9aa5b4;
    --accent: #8ea4ff;
    --accent-hover: #a8b9ff;
    --accent-soft: #1d2540;
    --on-accent: #0e1116;
    --ok: #5fd39b;
    --ok-bg: #12261d;
    --ok-border: #2c5c44;
    --warn: #e8b464;
    --warn-bg: #2a2114;
    --warn-border: #5e4926;
    --danger: #f08a8a;
    --danger-bg: #2c1719;
    --danger-border: #5e2f32;
    --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 4px 16px rgba(0, 0, 0, .3);
  }
}

html { -webkit-text-size-adjust: 100%; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  font-size: 16px;
  line-height: 1.55;
  overflow-wrap: break-word;
}

/* ---- header / nav ---- */

.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}

.topbar-inner {
  max-width: 72rem;
  margin: 0 auto;
  padding: 0.6rem 1rem;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 1rem;
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 0.55rem;
  font-weight: 700;
  font-size: 1.05rem;
  letter-spacing: -0.01em;
  color: var(--text);
  text-decoration: none;
  flex: 0 0 auto;
}

.brand-mark {
  width: 1.85rem;
  height: 1.85rem;
  border-radius: 8px;
  background: linear-gradient(140deg, var(--accent), #7b5cf0);
  color: #fff;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.95rem;
  font-weight: 800;
}

nav.sections {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  margin-left: auto;
}

nav.sections a {
  display: inline-block;
  padding: 0.5rem 0.75rem;
  border-radius: 999px;
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.95rem;
  font-weight: 500;
  min-height: 2.5rem;
  line-height: 1.5rem;
}

nav.sections a:hover, nav.sections a:focus-visible {
  background: var(--surface-2);
  color: var(--text);
}

nav.sections a[aria-current="page"] {
  background: var(--accent-soft);
  color: var(--accent);
  font-weight: 650;
}

/* On a phone the nav wraps to a second row. Two rows of sticky chrome would
   eat ~17% of the viewport on every page, so below this width the header
   scrolls away with the content instead. */
@media (max-width: 560px) {
  .topbar { position: static; }
  .topbar-inner { padding: 0.5rem 0.9rem; gap: 0.35rem 0.5rem; }
  nav.sections { margin-left: 0; width: 100%; }
  nav.sections a { padding: 0.4rem 0.6rem; font-size: 0.9rem; min-height: 2.25rem; }
}

/* ---- page frame ---- */

main {
  max-width: 72rem;
  margin: 0 auto;
  padding: 1.5rem 1rem 4rem;
}

h1 {
  font-size: clamp(1.45rem, 1.15rem + 1.4vw, 2rem);
  line-height: 1.2;
  letter-spacing: -0.02em;
  margin: 0 0 0.35rem;
}

h2 {
  font-size: 1.15rem;
  letter-spacing: -0.01em;
  margin: 0 0 0.75rem;
}

h3 {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  margin: 1rem 0 0.35rem;
}

p { margin: 0 0 0.75rem; }
.lede { color: var(--text-muted); max-width: 60ch; }
.muted { color: var(--text-muted); }
.mono { font-family: var(--mono); font-size: 0.92em; }

a { color: var(--accent); text-underline-offset: 2px; }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}

.page-head { margin-bottom: 1.25rem; }

/* ---- cards & callouts ---- */

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1.1rem;
  margin: 0 0 1.25rem;
}

.card > :last-child { margin-bottom: 0; }

.callout {
  border: 1px solid var(--border);
  border-left: 4px solid var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--surface);
  padding: 0.85rem 1rem;
  margin: 0 0 1.25rem;
}

.callout > :last-child { margin-bottom: 0; }
.callout-attention { border-color: var(--warn-border); border-left-color: var(--warn); background: var(--warn-bg); color: var(--warn); }
.callout-attention a { color: inherit; }
.callout-calm { border-color: var(--ok-border); border-left-color: var(--ok); background: var(--ok-bg); color: var(--ok); }
.callout-danger { border-color: var(--danger-border); border-left-color: var(--danger); background: var(--danger-bg); color: var(--danger); }

.grant-block {
  border: 1px solid var(--ok-border);
  border-top: 4px solid var(--ok);
  background: var(--surface);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1.1rem;
  margin: 0 0 1.25rem;
}

.context-block {
  border: 1px dashed var(--warn-border);
  border-top: 4px solid var(--warn);
  background: var(--surface);
  border-radius: var(--radius);
  padding: 1.1rem;
  margin: 0 0 1.25rem;
}

.grant-block > :last-child, .context-block > :last-child { margin-bottom: 0; }

.caveat { color: var(--warn); font-weight: 600; }
.callout-danger .caveat, .callout-attention .caveat { color: inherit; }

.block-label {
  display: block;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  font-weight: 700;
  color: var(--text-muted);
  margin-bottom: 0.2rem;
}

/* ---- stat grid (overview) ---- */

.stats {
  display: grid;
  /* min(…, 100%) so the track can shrink below its ideal width instead of
     overflowing on a narrow phone or at a large text size. */
  grid-template-columns: repeat(auto-fit, minmax(min(15rem, 100%), 1fr));
  gap: 0.85rem;
  margin: 0 0 1.5rem;
  padding: 0;
  list-style: none;
}

.stat {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 1rem;
  text-decoration: none;
  color: inherit;
}

.stat:hover, .stat:focus-visible { border-color: var(--accent); }
.stat-name { font-weight: 650; font-size: 0.95rem; color: var(--accent); }
.stat-value { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.2; }
.stat-desc { font-size: 0.87rem; color: var(--text-muted); }
.stat-alert .stat-value { color: var(--warn); }

/* ---- badges ---- */

.badge {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  border: 1px solid var(--border-strong);
  background: var(--surface-2);
  color: var(--text-muted);
  font-size: 0.78rem;
  font-weight: 650;
  line-height: 1.45;
  white-space: nowrap;
}

.badge-ok { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok); }
.badge-warn { background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn); }
.badge-danger { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger); }
.badge-accent { background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }

/* ---- tables ---- */

.table-wrap {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: var(--shadow);
  overflow-x: auto;
  margin: 0 0 1.25rem;
}

table { border-collapse: collapse; width: 100%; }

th, td {
  padding: 0.65rem 0.9rem;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--border);
}

thead th {
  background: var(--surface-2);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  white-space: nowrap;
}

tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--bg-accent); }
td.numeric, th.numeric { font-variant-numeric: tabular-nums; }
td .row-actions { display: flex; flex-wrap: wrap; gap: 0.4rem; }

/* Key/value tables inside the grant block. */
.kv { width: 100%; }
.kv th {
  width: 13rem;
  background: transparent;
  font-weight: 600;
  color: var(--text-muted);
  font-size: 0.9rem;
}
.kv tr:last-child th, .kv tr:last-child td { border-bottom: 0; }

@media (max-width: 720px) {
  .kv th, .kv td { display: block; width: auto; border-bottom: 0; padding: 0.15rem 0; }
  .kv th { padding-top: 0.6rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; }
  .kv tr { display: block; border-bottom: 1px solid var(--border); padding-bottom: 0.55rem; }
  .kv tr:last-child { border-bottom: 0; }
  .kv { border-collapse: separate; }
}

/* Wide record tables restyle into one card per row on narrow screens. */
@media (max-width: 800px) {
  .stack-wrap { border: 0; background: transparent; box-shadow: none; overflow: visible; }
  .stack thead { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
  .stack, .stack tbody, .stack tr, .stack td { display: block; }
  .stack tr {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    margin-bottom: 0.85rem;
    padding: 0.25rem 0.15rem;
  }
  .stack tbody tr:hover td { background: transparent; }
  .stack td {
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 1rem;
    align-items: baseline;
    justify-content: space-between;
    padding: 0.5rem 0.85rem;
  }
  .stack td::before {
    content: attr(data-label);
    flex: 0 0 auto;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 700;
    color: var(--text-muted);
  }
  .stack td:last-child { border-bottom: 0; }
  .stack td.actions { justify-content: flex-start; }
  .stack td.actions::before { content: none; }
  .stack td > * { min-width: 0; }
}

/* ---- forms ---- */

form { margin: 0; }
form.inline { display: inline-block; }

fieldset {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.9rem 1rem 1rem;
  margin: 0 0 1rem;
  min-width: 0;
}

legend {
  padding: 0 0.4rem;
  font-size: 0.85rem;
  font-weight: 650;
  color: var(--text-muted);
}

label {
  display: block;
  margin: 0 0 0.85rem;
  font-size: 0.92rem;
  font-weight: 550;
}

label > .muted { font-weight: 400; }

.field-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(16rem, 100%), 1fr));
  gap: 0 1rem;
}

input[type="text"], input[type="number"], input[type="password"],
input[type="datetime-local"], select, textarea {
  display: block;
  width: 100%;
  margin-top: 0.3rem;
  padding: 0.6rem 0.7rem;
  min-height: 2.75rem;
  font: inherit;
  font-size: 1rem; /* keeps iOS from zooming on focus */
  color: var(--text);
  background: var(--surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
}

textarea { min-height: 5.5rem; resize: vertical; font-family: var(--mono); font-size: 0.95rem; }

input:focus, select:focus, textarea:focus {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
  border-color: var(--accent);
}

label.check {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  font-weight: 400;
  line-height: 1.45;
}

label.check input[type="checkbox"] {
  width: 1.15rem;
  height: 1.15rem;
  margin: 0.2rem 0 0;
  flex: 0 0 auto;
  accent-color: var(--accent);
}

.actions-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 0.6rem;
  align-items: center;
  margin-top: 0.5rem;
}

button, .btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  min-height: 2.75rem;
  padding: 0.55rem 1.1rem;
  font: inherit;
  font-weight: 600;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong);
  background: var(--surface);
  color: var(--text);
  cursor: pointer;
  text-decoration: none;
}

button:hover, .btn:hover { border-color: var(--accent); color: var(--accent); }

button.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--on-accent);
}
button.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); color: var(--on-accent); }

button.danger { color: var(--danger); border-color: var(--danger-border); background: var(--danger-bg); }
button.danger:hover { border-color: var(--danger); color: var(--danger); }

button.small, .btn.small { min-height: 2.25rem; padding: 0.3rem 0.8rem; font-size: 0.88rem; }

.btn-link {
  display: inline-flex;
  align-items: center;
  min-height: 2.25rem;
  font-weight: 600;
  text-decoration: none;
}
.btn-link:hover { text-decoration: underline; }

/* ---- misc ---- */

pre {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.8rem;
  margin: 0 0 0.75rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--mono);
  font-size: 0.88rem;
}

.empty {
  text-align: center;
  padding: 2.25rem 1rem;
  color: var(--text-muted);
  background: var(--surface);
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  margin: 0 0 1.25rem;
}

.empty p { margin: 0; }

.list-plain { list-style: none; margin: 0; padding: 0; }
.list-plain li + li { margin-top: 0.15rem; }

@media (prefers-reduced-motion: no-preference) {
  a, button, .btn, .stat { transition: background-color .12s ease, border-color .12s ease, color .12s ease; }
}
"#;

fn layout(title: &str, body: Markup) -> Markup {
    layout_at(title, None, body)
}

/// `current` is the nav href to mark as the active section (`aria-current`).
fn layout_at(title: &str, current: Option<&str>, body: Markup) -> Markup {
    const SECTIONS: [(&str, &str); 5] = [
        ("/", "Overview"),
        ("/ui/requests", "Requests"),
        ("/ui/grants", "Grants"),
        ("/ui/policies", "Policies"),
        ("/ui/secrets", "Secrets"),
    ];
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light dark";
                title { (title) " — Keychute" }
                style { (maud::PreEscaped(STYLE)) }
            }
            body {
                header .topbar {
                    div .topbar-inner {
                        a .brand href="/" {
                            span .brand-mark aria-hidden="true" { "K" }
                            span { "Keychute" }
                        }
                        nav .sections aria-label="Sections" {
                            @for (href, label) in SECTIONS {
                                a href=(href) aria-current=[
                                    (current == Some(href)).then_some("page")
                                ] { (label) }
                            }
                        }
                    }
                }
                main { (body) }
            }
        }
    }
}

fn html_page_at(title: &str, current: &str, body: Markup) -> Html<String> {
    Html(layout_at(title, Some(current), body).into_string())
}

/// Short badge for a tier: the long [`Tier::human_label`] belongs in the
/// grant block, not in a table cell that has to fit on a phone.
fn tier_badge(tier: Tier) -> Markup {
    let class = match tier {
        Tier::Brokered => "badge badge-ok",
        Tier::TrustedClient => "badge",
        Tier::CooperatingClient => "badge badge-warn",
        Tier::Direct => "badge badge-danger",
    };
    html! { span class=(class) title=(tier.human_label()) { (tier.as_str()) } }
}

/// Badge for a mechanism string as stored (may be an unknown legacy value).
fn mechanism_badge(mechanism: &str) -> Markup {
    html! { span .badge .mono { (mechanism) } }
}

fn policy_outcome_badge(outcome: &str) -> Markup {
    let class = match outcome {
        "auto-approve" => "badge badge-warn",
        "deny" => "badge badge-danger",
        "notify-only" => "badge",
        _ => "badge badge-ok",
    };
    html! { span class=(class) { (outcome) } }
}

/// Page title plus optional one-line explanation, shared by every section.
fn page_head(title: &str, lede: Markup) -> Markup {
    html! {
        div .page-head {
            h1 { (title) }
            p .lede { (lede) }
        }
    }
}

fn empty_state(msg: &str) -> Markup {
    html! { div .empty { p { (msg) } } }
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
            span .block-label { "What the server will enforce" }
            h2 { "What you are approving" }
            table .kv {
                tr { th { "Secret" } td { (secret_line) } }
                tr { th { "Mechanism" } td { (mechanism_badge(mechanism.as_str())) } }
                tr { th { "Tier" } td { (tier.human_label()) } }
                tr { th { "Origins" }
                    td {
                        @if constraints.origins.is_empty() { span .muted { "(none)" } }
                        @else {
                            ul .list-plain {
                                @for o in &constraints.origins { li .mono { (o.to_display()) } }
                            }
                        }
                    }
                }
                tr { th { "Methods" }
                    td {
                        @if constraints.methods.is_empty() { span .muted { "(none)" } }
                        @else { span .mono { (constraints.methods.join(", ")) } }
                    }
                }
                tr { th { "Path prefixes" }
                    td {
                        @if constraints.path_prefixes.is_empty() { span .muted { "(none)" } }
                        @else {
                            ul .list-plain {
                                @for p in &constraints.path_prefixes { li .mono { (p) } }
                            }
                        }
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
            span .block-label { "What the client claims" }
            h2 { "Context supplied by the client" }
            p .muted {
                "An agent under prompt injection can put anything here. None of it "
                "is checked, and none of it changes what the server enforces."
            }
            @if mechanism == Mechanism::CliRead {
                p .caveat {
                    "Tier-2 caveat: this is tagged as coming from the keychute CLI, "
                    "but the reason above is the agent's own words — and the agent can "
                    "read the released secret from stdout."
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

    Ok(html_page_at(
        "Overview",
        "/",
        html! {
            (page_head("Keychute", html! {
                "Secrets broker for AI agents. You pick the risk tier of every "
                "delivery path; every release is either matched by a standing policy "
                "or approved here, by you."
            }))
            p .muted { "Signed in as " span .mono { (op.subject) } "." }

            @if pending > 0 {
                div .callout .callout-attention {
                    p {
                        b {
                            (pending)
                            @if pending == 1 { " request is" } @else { " requests are" }
                            " waiting for your decision."
                        }
                        " "
                        a href="/ui/requests" { "Review now" }
                    }
                }
            } @else {
                div .callout .callout-calm {
                    p { "Nothing is waiting for your decision." }
                }
            }

            // Each tile is the section link itself: on a phone the whole card
            // is the tap target, not a word inside a table cell.
            ul .stats {
                li {
                    a .stat .stat-alert[pending > 0] href="/ui/requests" {
                        span .stat-name { "Requests" }
                        span .stat-value { (pending) " pending" }
                        span .stat-desc { "Access requests awaiting approval or denial." }
                    }
                }
                li {
                    a .stat href="/ui/grants" {
                        span .stat-name { "Grants" }
                        span .stat-value { (grants) " active" }
                        span .stat-desc { "Live grants; revoke one to cut off access immediately." }
                    }
                }
                li {
                    a .stat href="/ui/policies" {
                        span .stat-name { "Policies" }
                        span .stat-value { (policies) }
                        // Not "auto-approve": a policy row's outcome is any of
                        // auto-approve, notify-only, require-approval or deny,
                        // and the count (like /ui/policies itself) covers all.
                        span .stat-desc { "Standing rules applied to a request before you see it." }
                    }
                }
                li {
                    a .stat href="/ui/secrets" {
                        span .stat-name { "Secrets" }
                        span .stat-value { (secrets) " stored" }
                        span .stat-desc { "Stored credentials, their max tier and injection style." }
                    }
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
    Ok(html_page_at(
        "Pending requests",
        "/ui/requests",
        html! {
            (page_head("Pending access requests", html! {
                "Each row is an agent waiting on you. Open one to see exactly what "
                "it would get."
            }))
            @if rows.is_empty() { (empty_state("No pending requests.")) }
            @else {
                div .table-wrap .stack-wrap {
                    table .stack {
                        thead {
                            tr {
                                th { "Client" } th { "Secret" } th { "Mechanism" }
                                th { "Tier" } th .numeric { "Age" } th { span .muted { "Action" } }
                            }
                        }
                        tbody {
                            @for r in &rows {
                                tr {
                                    td data-label="Client" { b { (r.client_name) } }
                                    td data-label="Secret" { span .mono { (r.secret_name) } }
                                    td data-label="Mechanism" { (mechanism_badge(&r.mechanism)) }
                                    td data-label="Tier" {
                                        @match Mechanism::from_str_opt(&r.mechanism) {
                                            Some(m) => { (tier_badge(m.tier())) }
                                            None => { span .badge .muted { "unknown" } }
                                        }
                                    }
                                    td .numeric data-label="Age" { (age_label(r.created_at, now)) }
                                    td .actions data-label="" {
                                        a .btn .small href={ "/ui/requests/" (r.id) } { "Review" }
                                    }
                                }
                            }
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
    "This secret changed while you were reviewing: it was stored, removed, or \
     rotated since the page loaded, so the form no longer meant what it said. \
     Nothing was approved. Check the details below and decide again.";

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
                span .mono { (s.name) } " "
                span .muted {
                    "(stored, version " (s.current_version)
                    ", max tier: "
                    (Tier::from_int(s.max_tier).map(|t| t.as_str()).unwrap_or("?"))
                    ")"
                }
            },
            None => html! { (row.secret_name) },
        };
        let badge_class = match label {
            "approved" => "badge badge-ok",
            "denied" => "badge badge-danger",
            _ => "badge badge-warn",
        };
        return Ok(html_page_at(
            "Request resolved",
            "/ui/requests",
            html! {
                div .page-head {
                    h1 { "Request from " (row.client_name) }
                    p .lede {
                        span class=(badge_class) { (label) }
                        " — this request can no longer be acted on."
                    }
                }
                div .card {
                    table .kv {
                        tr { th { "Age" } td { "Created " (age_label(row.created_at, now)) " ago" } }
                        @if let Some(by) = &row.resolved_by {
                            tr { th { "Resolved by" } td { (by) } }
                        }
                        @if let Some(at) = row.resolved_at {
                            tr { th { "Resolved at" } td { (at.format("%Y-%m-%d %H:%M:%S UTC")) } }
                        }
                        @if let Some(reason) = &row.deny_reason {
                            tr { th { "Deny reason" } td { (reason) } }
                        }
                    }
                }
                (grant_block(mechanism, &constraints, secret_line))
                (context_block(context.as_ref(), mechanism))
                p { a .btn-link href="/ui/requests" { "← Back to pending requests" } }
            },
        ));
    }
    if policy_cap_elapsed(row.policy_not_after, now) {
        return Ok(html_page_at(
            "Request no longer approvable",
            "/ui/requests",
            html! {
                div .page-head {
                    h1 { "Request no longer approvable" }
                    p .lede .mono { (row.id) }
                }
                div .callout .callout-danger {
                    p {
                        "The standing policy this request matched has "
                        b { "expired" }
                        ", so any grant issued now would already be past its cap. "
                        "This request can no longer be approved and must be re-submitted \
                         by the client."
                    }
                }
                p { a .btn-link href="/ui/requests" { "← Back to pending requests" } }
            },
        ));
    }
    let mechanism = parse_mechanism(&row.mechanism)?;
    let constraints = parse_constraints(row)?;
    let secret = db::get_secret_by_name(&state.db, &row.secret_name).await?;
    let context = decrypt_context(state, row);

    let secret_line = match &secret {
        Some(s) => html! {
            span .mono { (s.name) } " "
            span .muted {
                "(stored, version " (s.current_version)
                ", max tier: "
                (Tier::from_int(s.max_tier).map(|t| t.as_str()).unwrap_or("?"))
                ")"
            }
            // Who put these bytes here matters to the decision: a deposited,
            // unreviewed value was chosen by the client, not by you.
            @if !s.operator_vetted {
                " "
                span .caveat { "(deposited by a client — not yet reviewed by you)" }
            }
        },
        None => html! {
            span .mono { (row.secret_name) } " "
            span .caveat { "(NOT stored in Keychute — value required below)" }
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

    Ok(html_page_at(
        "Approve request",
        "/ui/requests",
        html! {
            div .page-head {
                h1 { "Access request from " (row.client_name) }
                p .lede {
                    "Created " (age_label(row.created_at, now)) " ago · expires at "
                    (row.expires_at.format("%Y-%m-%d %H:%M:%S UTC"))
                }
            }
            @if let Some(text) = notice {
                div .callout .callout-danger {
                    p .caveat { (text) }
                }
            }
            (grant_block(mechanism, &constraints, secret_line))
            (context_block(context.as_ref(), mechanism))

            div .card {
                h2 { "Your decision" }
                form method="post" action={ "/ui/requests/" (id) "/approve" } {
                    input type="hidden" name="csrf_token" value=(approve_token);
                    input type="hidden" name=(F_SECRET_PRESENT) value=(secret_present);
                    fieldset {
                        legend { "Narrow the grant (optional)" }
                        p .muted { "Either value can only shrink what was requested." }
                        div .field-grid {
                            label {
                                "TTL seconds (≤ " (constraints.ttl_seconds) ")"
                                input type="number" name="ttl_seconds" min="1" inputmode="numeric"
                                    max=(constraints.ttl_seconds) placeholder=(constraints.ttl_seconds);
                            }
                            label {
                                "Max uses"
                                input type="number" name="max_uses" min="1" inputmode="numeric";
                            }
                        }
                    }
                    @if secret.is_none() {
                        fieldset {
                            legend { "Secret value (not yet stored)" }
                            label {
                                "Secret value"
                                input type="password" name="secret_value" autocomplete="off"
                                    autocapitalize="off" autocorrect="off" spellcheck="false";
                            }
                            label .check {
                                input type="checkbox" name="store_secret" value="on";
                                span {
                                    "Store this secret in Keychute"
                                    br;
                                    span .muted { "Otherwise it is released once, to this grant only." }
                                }
                            }
                            label {
                                "Max tier when stored: " b { (default_tier.as_str()) }
                                input type="hidden" name="store_max_tier" value=(default_tier.as_str());
                                span .muted {
                                    " — fixed to the tier you are approving. Widen it later from "
                                    "the secrets page if you mean to."
                                }
                            }
                            div .field-grid {
                                label {
                                    "Injection kind"
                                    select name="injection_kind" {
                                        option value="bearer" selected { "bearer (Authorization: Bearer …)" }
                                        option value="header" { "header (named header)" }
                                        option value="basic" { "basic-password (Authorization: Basic)" }
                                    }
                                }
                                label {
                                    "Header name / basic-auth username"
                                    input type="text" name="injection_header"
                                        autocapitalize="off" autocorrect="off" spellcheck="false";
                                    span .muted { "Only for kinds " b { "header" } " and " b { "basic-password" } "." }
                                }
                            }
                            label {
                                "Description"
                                input type="text" name="store_description";
                            }
                        }
                    }
                    div .actions-bar {
                        button .primary type="submit" { "Approve" }
                    }
                }
                div .actions-bar {
                    form method="post" action={ "/ui/requests/" (id) "/deny" } .inline {
                        input type="hidden" name="csrf_token" value=(deny_token);
                        button .danger type="submit" { "Deny" }
                    }
                    a .btn-link href="/ui/requests" { "Decide later" }
                }
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

/// Operator-facing wrapper around [`crate::injection::validate_injection`]
/// (shared with the client deposit endpoint): same rules, UI error shape.
#[allow(clippy::type_complexity)]
fn validate_injection(
    kind: &str,
    header: Option<&str>,
) -> UiResult<(String, Option<String>, Option<String>)> {
    crate::injection::validate_injection(kind, header).map_err(UiError::bad_request)
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
    match approved {
        db::ui_ext::ApproveOutcome::Approved(_) => {}
        db::ui_ext::ApproveOutcome::NotApprovable => {
            return Err(UiError::new(
                StatusCode::CONFLICT,
                "request was resolved or expired concurrently",
            ));
        }
        db::ui_ext::ApproveOutcome::SecretNameTaken => {
            // A client deposit (or another operator) stored that name between
            // this page rendering and the approve. Nothing was approved and
            // nothing was overwritten: re-render so the operator decides
            // against the secret that now exists.
            return Err(UiError::new(
                StatusCode::CONFLICT,
                "a secret with that name was stored while you were reviewing. \
                 Nothing was approved — reload the request and decide against \
                 the secret that is now stored.",
            ));
        }
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
    Ok(html_page_at(
        "Active grants",
        "/ui/grants",
        html! {
            (page_head("Active grants", html! {
                "Live access a client is holding right now. Revoking one cuts it "
                "off immediately."
            }))
            @if grants.is_empty() { (empty_state("No active grants.")) }
            @else {
                div .table-wrap .stack-wrap {
                    table .stack {
                        thead {
                            tr {
                                th { "Client" } th { "Secret" } th { "Mechanism" }
                                th { "Expires" } th .numeric { "Uses" } th { span .muted { "Action" } }
                            }
                        }
                        tbody {
                            @for g in &grants {
                                tr {
                                    td data-label="Client" { b { (g.client_name) } }
                                    td data-label="Secret" { span .mono { (g.secret_name) } }
                                    td data-label="Mechanism" { (mechanism_badge(&g.mechanism)) }
                                    td data-label="Expires" { (g.not_after.format("%Y-%m-%d %H:%M:%S UTC")) }
                                    td .numeric data-label="Uses" {
                                        (g.use_count) " / "
                                        @match g.max_uses {
                                            Some(m) => { (m) }
                                            None => { "unlimited" }
                                        }
                                    }
                                    td .actions data-label="" {
                                        form method="post" action={ "/ui/grants/" (g.id) "/revoke" } .inline {
                                            input type="hidden" name="csrf_token"
                                                value=(csrf::issue_token(&state.keyset, R_REVOKE, &g.id.to_string(), &op.subject, "", now));
                                            button .danger .small type="submit" { "Revoke" }
                                        }
                                    }
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
    // Named on this page because it is where consent gets expressed: a client
    // can squat a name BEFORE the operator writes the matching rule, and the
    // unvetted clamp is what makes that harmless. Saying so here is what makes
    // it visible.
    let unvetted = db::list_unvetted_secret_names(&state.db).await?;
    let create_token = csrf::issue_token(&state.keyset, R_POLICY_CREATE, "", &op.subject, "", now);
    Ok(html_page_at(
        "Policies",
        "/ui/policies",
        html! {
            (page_head("Standing policies", html! {
                "Applied before a request ever reaches you. A matching deny wins "
                "outright; otherwise the most specific match does — naming a client, "
                "then a secret, outranks a wildcard, and Priority only breaks ties "
                "between rows of equal specificity."
            }))
            @if policies.is_empty() { (empty_state("No policy rows.")) }
            @else {
                div .table-wrap .stack-wrap {
                    table .stack {
                        thead {
                            tr {
                                th { "Client" } th { "Secret" } th { "Mechanism" } th { "Outcome" }
                                th .numeric { "Priority" } th { "Limits" } th { "Not after" }
                                th { "By" } th { span .muted { "Action" } }
                            }
                        }
                        tbody {
                            @for p in &policies {
                                tr {
                                    td data-label="Client" {
                                        @match &p.client_name {
                                            Some(c) => { b { (c) } }
                                            None => { span .muted { "any" } }
                                        }
                                    }
                                    td data-label="Secret" {
                                        @if let Some(s) = &p.secret_name { span .mono { (s) } }
                                        @else if let Some(t) = &p.secret_tag { span .mono { "tag:" (t) } }
                                        @else { span .muted { "any" } }
                                    }
                                    td data-label="Mechanism" { (mechanism_badge(&p.mechanism)) }
                                    td data-label="Outcome" { (policy_outcome_badge(&p.outcome)) }
                                    td .numeric data-label="Priority" { (p.priority) }
                                    td data-label="Limits" {
                                        @if p.max_ttl_seconds.is_none() && p.max_uses.is_none() {
                                            span .muted { "—" }
                                        }
                                        @if let Some(ttl) = p.max_ttl_seconds { "ttl ≤ " (ttl) "s" }
                                        @if p.max_ttl_seconds.is_some() && p.max_uses.is_some() { " · " }
                                        @if let Some(u) = p.max_uses { "uses ≤ " (u) }
                                    }
                                    td data-label="Not after" {
                                        @match p.not_after {
                                            Some(t) => { (t.format("%Y-%m-%d %H:%M UTC")) }
                                            None => { span .muted { "—" } }
                                        }
                                    }
                                    td data-label="By" { span .muted { (p.created_by) } }
                                    td .actions data-label="" {
                                        form method="post" action={ "/ui/policies/" (p.id) "/delete" } .inline {
                                            input type="hidden" name="csrf_token"
                                                value=(csrf::issue_token(&state.keyset, R_POLICY_DELETE, &p.id.to_string(), &op.subject, "", now));
                                            button .danger .small type="submit" { "Delete" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div .card {
                h2 { "Create policy" }
                @if !unvetted.is_empty() {
                    div .callout .callout-attention {
                        p {
                            "Heads up: these secrets were deposited by a client and "
                            "nobody has reviewed them — "
                            @for (i, name) in unvetted.iter().enumerate() {
                                @if i > 0 { ", " }
                                span .mono { (name) }
                            }
                            ". A rule you write now will not auto-release them until "
                            "you review each one on the secrets page, so a client "
                            "cannot claim a name ahead of a policy you are about to "
                            "write."
                        }
                    }
                }
                form method="post" action="/ui/policies" {
                    input type="hidden" name="csrf_token" value=(create_token);
                    fieldset {
                        legend { "What it matches" }
                        div .field-grid {
                            label {
                                "Client name " span .muted { "(blank = any)" }
                                input type="text" name="client_name"
                                    autocapitalize="off" autocorrect="off" spellcheck="false";
                            }
                            label {
                                "Secret name " span .muted { "(blank = any)" }
                                input type="text" name="secret_name"
                                    autocapitalize="off" autocorrect="off" spellcheck="false";
                            }
                            label {
                                "…or secret tag"
                                input type="text" name="secret_tag"
                                    autocapitalize="off" autocorrect="off" spellcheck="false";
                            }
                            label {
                                "Mechanism"
                                select name="mechanism" {
                                    option value="brokered" { "brokered" }
                                    option value="autofill" { "autofill" }
                                    option value="cli-read" { "cli-read" }
                                    option value="direct-read" { "direct-read" }
                                }
                            }
                        }
                    }
                    fieldset {
                        legend { "What it does" }
                        div .field-grid {
                            label {
                                "Outcome"
                                select name="outcome" {
                                    option value="require-approval" { "require-approval" }
                                    option value="notify-only" { "notify-only" }
                                    option value="auto-approve" { "auto-approve" }
                                    option value="deny" { "deny" }
                                }
                            }
                            label {
                                "Priority"
                                input type="number" name="priority" value="0" inputmode="numeric";
                            }
                        }
                    }
                    fieldset {
                        legend { "Constraints" }
                        label {
                            "Origins " span .muted { "(host[:port], one per line)" }
                            textarea name="origins" rows="3"
                                autocapitalize="off" autocorrect="off" spellcheck="false" {}
                        }
                        label {
                            "Methods " span .muted { "(comma/space separated, blank = unconstrained)" }
                            input type="text" name="methods"
                                autocapitalize="characters" autocorrect="off" spellcheck="false";
                        }
                        label {
                            "Path prefixes " span .muted { "(one per line, blank = unconstrained)" }
                            textarea name="path_prefixes" rows="3"
                                autocapitalize="off" autocorrect="off" spellcheck="false" {}
                        }
                        div .field-grid {
                            label {
                                "Max TTL seconds"
                                input type="number" name="max_ttl_seconds" min="1" inputmode="numeric";
                            }
                            label {
                                "Max uses"
                                input type="number" name="max_uses" min="1" inputmode="numeric";
                            }
                            label {
                                "Not after (UTC)"
                                input type="datetime-local" name="not_after";
                            }
                        }
                    }
                    div .actions-bar {
                        button .primary type="submit" { "Create policy" }
                    }
                }
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
    Ok(html_page_at(
        "Secrets",
        "/ui/secrets",
        html! {
            (page_head("Stored secrets", html! {
                "Credentials Keychute holds. Each one is capped at the broadest tier "
                "it can ever be released through."
            }))
            @if secrets.iter().any(|s| !s.operator_vetted) {
                div .callout .callout-attention {
                    p {
                        "Some secrets below were deposited by a client and nobody has "
                        "reviewed them. Until you do, every release of them needs your "
                        "approval — a standing auto-approve or notify-only policy will "
                        "NOT release a secret you have never seen. "
                        "\"Review value\" shows you the credential the client stored."
                    }
                }
            }
            @if secrets.is_empty() { (empty_state("No stored secrets.")) }
            @else {
                div .table-wrap .stack-wrap {
                    table .stack {
                        thead {
                            tr {
                                th { "Name" } th { "Description" } th .numeric { "Version" }
                                th { "Max tier" } th { "Injection" } th { "Enabled" }
                                th { "Reviewed" } th { "" }
                            }
                        }
                        tbody {
                            @for s in &secrets {
                                tr {
                                    td data-label="Name" { b .mono { (s.name) } }
                                    td data-label="Description" {
                                        @if s.description.is_empty() { span .muted { "—" } }
                                        @else { (s.description) }
                                    }
                                    td .numeric data-label="Version" { (s.current_version) }
                                    td data-label="Max tier" {
                                        @match Tier::from_int(s.max_tier) {
                                            Some(t) => { (tier_badge(t)) }
                                            None => { span .badge .muted { "?" } }
                                        }
                                    }
                                    td data-label="Injection" {
                                        span .mono {
                                            (s.injection_kind)
                                            // Both free-text fields are shown: for kind 'basic'
                                            // the account identity lives in injection_username,
                                            // and the proxy builds the Authorization header from
                                            // it — an operator vetting a deposit has to see whose
                                            // account the client picked.
                                            @if let Some(h) = &s.injection_header { " (" (h) ")" }
                                            @if let Some(u) = &s.injection_username { " (user: " (u) ")" }
                                        }
                                    }
                                    td data-label="Enabled" {
                                        @if s.enabled { span .badge .badge-ok { "yes" } }
                                        @else { span .badge .badge-danger { "no" } }
                                    }
                                    td data-label="Reviewed" {
                                        @if s.operator_vetted { span .badge .badge-ok { "yes" } }
                                        @else {
                                            span .badge .badge-warn { "not yet" }
                                        }
                                    }
                                    td .actions data-label="" {
                                        @if !s.operator_vetted {
                                            form method="post"
                                                action={ "/ui/secrets/" (s.id) "/review" } .inline {
                                                input type="hidden" name="csrf_token"
                                                    value=(csrf::issue_token(&state.keyset, R_SECRET_REVEAL, &s.id.to_string(), &op.subject, "", now));
                                                button .small type="submit" { "Review value" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div .card {
                h2 { "Create or rotate a secret" }
                p .muted {
                    "If the name matches an existing secret the value is rotated in as a "
                    "new version (other fields are ignored); otherwise a new secret is created."
                }
                form method="post" action="/ui/secrets" {
                    input type="hidden" name="csrf_token" value=(token);
                    div .field-grid {
                        label {
                            "Name"
                            input type="text" name="name" required
                                autocapitalize="off" autocorrect="off" spellcheck="false";
                        }
                        label {
                            "Value"
                            input type="password" name="secret_value" autocomplete="off" required
                                autocapitalize="off" autocorrect="off" spellcheck="false";
                        }
                        label {
                            "Description"
                            input type="text" name="description";
                        }
                        label {
                            "Max tier"
                            select name="max_tier" {
                                @for t in [Tier::Brokered, Tier::TrustedClient, Tier::CooperatingClient, Tier::Direct] {
                                    option value=(t.as_str()) selected[t == Tier::Brokered] { (t.as_str()) }
                                }
                            }
                        }
                        label {
                            "Injection kind"
                            select name="injection_kind" {
                                option value="bearer" selected { "bearer" }
                                option value="header" { "header" }
                                option value="basic" { "basic-password" }
                            }
                        }
                        label {
                            "Header name / basic-auth username"
                            input type="text" name="injection_header"
                                autocapitalize="off" autocorrect="off" spellcheck="false";
                            span .muted { "Only for kinds " b { "header" } " and " b { "basic-password" } "." }
                        }
                    }
                    div .actions-bar {
                        button .primary type="submit" { "Save" }
                    }
                }
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

#[derive(Deserialize)]
struct ReviewForm {
    csrf_token: String,
    /// Present when the operator explicitly asked to see the plaintext.
    #[serde(default)]
    reveal: Option<String>,
}

/// Standing rows that would begin releasing this secret WITHOUT a human the
/// moment it is vetted — the actual consequence of the button, and the thing an
/// operator can meaningfully weigh.
///
/// Deliberately selector-only (client, name/tag/wildcard, live) rather than a
/// full policy evaluation: there is no request to evaluate yet, and listing a
/// superset is the safe direction for a warning.
fn policies_activated_by_vetting<'a>(
    policies: &'a [db::PolicyRow],
    secret_name: &str,
    tags: &[String],
    now: DateTime<Utc>,
) -> Vec<&'a db::PolicyRow> {
    policies
        .iter()
        .filter(|p| matches!(p.outcome.as_str(), "auto-approve" | "notify-only"))
        .filter(|p| p.not_after.is_none_or(|t| t > now))
        .filter(|p| match (&p.secret_name, &p.secret_tag) {
            (Some(name), _) => name == secret_name,
            (None, Some(tag)) => tags.contains(tag),
            (None, None) => true,
        })
        .collect()
}

/// POST /ui/secrets/{id}/review — the decision page for a client deposit.
///
/// Leads with what an operator can actually judge: which client put this here
/// and when, the injection template (for kind 'basic' that is an account
/// identity the client chose), the tier cap, and — the point of the page —
/// which standing policies would start releasing it with no human once it is
/// vetted. A credential's BYTES are not judgeable by eye; its provenance and
/// its consequences are.
///
/// The plaintext is therefore shown only when explicitly asked for (`reveal`),
/// and only that path decrypts and audits `secret-revealed`. POST, not GET: a
/// URL that renders a secret would land in browser history and be re-fetchable.
///
/// The confirmation form is bound to the version displayed here, so a rotation
/// landing in between cannot get unseen bytes vetted.
async fn review_secret(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<ReviewForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    check_post(
        &state,
        &headers,
        R_SECRET_REVEAL,
        &id.to_string(),
        &op.subject,
        "",
        &form.csrf_token,
    )?;
    let secret = db::list_secrets(&state.db)
        .await?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| UiError::new(StatusCode::NOT_FOUND, "no such secret"))?;
    if secret.operator_vetted {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "that secret is already marked reviewed",
        ));
    }
    let version = db::get_secret_version(&state.db, secret.id, secret.current_version)
        .await?
        .ok_or_else(|| UiError::new(StatusCode::NOT_FOUND, "no stored version to review"))?;
    let now = Utc::now();
    let origin = db::client_deposit_origin(&state.db, &secret.name).await?;
    let tags = db::get_tags_for_secret(&state.db, secret.id).await?;
    let policies = db::list_policies(&state.db).await?;
    let activated = policies_activated_by_vetting(&policies, &secret.name, &tags, now);

    // Only the explicit reveal decrypts, and only it is audited: seeing a
    // credential is an event, but opening the decision page is not.
    let revealed = match form.reveal.as_deref() {
        Some("1") => {
            let plaintext = state
                .keyset
                .open(
                    &version.ciphertext,
                    &version.nonce,
                    &version.wrapped_dek,
                    &version.kek_id,
                    AadContext::SecretVersion {
                        secret_id: secret.id,
                        version: version.version,
                    },
                )
                .map_err(|e| {
                    tracing::warn!(secret_id = %secret.id, error = %e, "secret version undecryptable");
                    UiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "that secret\'s stored value could not be decrypted",
                    )
                })?;
            audit::insert_audit(
                &state.db,
                &audit::AuditEvent {
                    kind: audit::kinds::SECRET_REVEALED,
                    secret_name: Some(secret.name.clone()),
                    secret_version_id: Some(version.id),
                    actor: Some(op.subject.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| UiError::from(anyhow::Error::from(e)))?;
            // A faithful rendering, or the operator is looking at something
            // other than what is stored. Valid UTF-8 goes out verbatim;
            // anything else (the CLI deposits non-UTF-8 credentials as base64,
            // and binary keys are a real case) is shown as base64 rather than
            // lossily mangled into replacement characters. Always a TEXT node —
            // auto-escaped like every other client-derived string — inside a
            // <pre>, so a PEM\'s line breaks survive the trip to the screen.
            use secrecy::ExposeSecret;
            let bytes = plaintext.expose_secret();
            Some(match std::str::from_utf8(bytes) {
                Ok(text) => (text.to_owned(), false),
                Err(_) => (
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                    true,
                ),
            })
        }
        _ => None,
    };

    let marker = version.version.to_string();
    let vet_token = csrf::issue_token(
        &state.keyset,
        R_SECRET_VET,
        &id.to_string(),
        &op.subject,
        &marker,
        now,
    );
    let reveal_token = csrf::issue_token(
        &state.keyset,
        R_SECRET_REVEAL,
        &id.to_string(),
        &op.subject,
        "",
        now,
    );
    Ok(html_page_at(
        "Review secret",
        "/ui/secrets",
        html! {
            (page_head("Review a deposited secret", html! {
                "A client stored this credential and nobody has reviewed it, so Keychute "
                "will not release it without your approval — not even under a standing "
                "auto-approve policy. Marking it reviewed lifts that."
            }))
            div .card {
                h2 { span .mono { (secret.name) } }
                table .kv {
                    tr {
                        th { "Deposited by" }
                        td {
                            @match &origin {
                                Some((client, at)) => {
                                    span .mono { (client) }
                                    " on " (at.format("%Y-%m-%d %H:%M UTC"))
                                }
                                // Belt and braces: an unvetted row with no
                                // client deposit audit row should not exist.
                                None => { span .muted { "unknown (no deposit record)" } }
                            }
                        }
                    }
                    tr { th { "Version" } td { (version.version) } }
                    tr {
                        th { "Max tier" }
                        td {
                            @match Tier::from_int(secret.max_tier) {
                                Some(t) => { (tier_badge(t)) }
                                None => { span .badge .muted { "?" } }
                            }
                        }
                    }
                    tr {
                        th { "Injection" }
                        td {
                            span .mono { (secret.injection_kind) }
                            @if let Some(h) = &secret.injection_header {
                                " into header " span .mono { (h) }
                            }
                            @if let Some(u) = &secret.injection_username {
                                " as user " span .mono { (u) }
                                " "
                                span .caveat { "(the account the client chose)" }
                            }
                        }
                    }
                    @if !secret.description.is_empty() {
                        tr { th { "Client description" } td { (secret.description) } }
                    }
                }
            }
            div .card {
                h2 { "What marking this reviewed allows" }
                @if activated.is_empty() {
                    p {
                        "No standing policy currently matches this secret, so releases "
                        "will keep coming to you for approval either way. Reviewing it "
                        "only means a future auto-approve or notify-only policy would "
                        "apply."
                    }
                } @else {
                    div .callout .callout-attention {
                        p {
                            "These standing policies would begin releasing this secret "
                            b { " without asking you" } ":"
                        }
                        ul {
                            @for p in &activated {
                                li {
                                    (policy_outcome_badge(&p.outcome)) " "
                                    span .mono { (p.mechanism) }
                                    " for client "
                                    span .mono {
                                        @match &p.client_name {
                                            Some(c) => { (c) }
                                            None => { "ANY CLIENT" }
                                        }
                                    }
                                    @match (&p.secret_name, &p.secret_tag) {
                                        (Some(_), _) => { " (this secret by name)" }
                                        (None, Some(tag)) => { " (tag " span .mono { (tag) } ")" }
                                        (None, None) => { " (any secret)" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div .card {
                h2 { "The stored value" }
                @match &revealed {
                    Some((shown, is_base64)) => {
                        @if *is_base64 {
                            p {
                                "As deposited — " b { "not valid UTF-8" }
                                ", shown base64-encoded:"
                            }
                        } @else {
                            p { "As deposited:" }
                        }
                        pre { (shown) }
                    }
                    None => {
                        p .muted {
                            "Hidden. A credential\'s bytes are rarely judgeable by eye — "
                            "the questions above usually decide this. Reveal it if you "
                            "need to compare it against something you already have; "
                            "doing so is recorded in the audit log."
                        }
                        form method="post" action={ "/ui/secrets/" (secret.id) "/review" } .inline {
                            input type="hidden" name="csrf_token" value=(reveal_token);
                            input type="hidden" name="reveal" value="1";
                            button .small type="submit" { "Reveal stored value" }
                        }
                    }
                }
            }
            div .card {
                p .muted {
                    "Marking this reviewed applies to version " (version.version)
                    " specifically. If it is rotated before you confirm, you will be "
                    "asked to look again."
                }
                div .actions-bar {
                    form method="post" action={ "/ui/secrets/" (secret.id) "/reviewed" } .inline {
                        input type="hidden" name="csrf_token" value=(vet_token);
                        input type="hidden" name="reviewed_version" value=(marker);
                        button .primary type="submit" {
                            "Mark reviewed (version " (version.version) ")"
                        }
                    }
                    a .button href="/ui/secrets" { "Back without reviewing" }
                }
            }
        },
    )
    .into_response())
}

#[derive(Deserialize)]
struct ReviewedForm {
    csrf_token: String,
    /// The version whose plaintext was displayed. Echoed back and bound into
    /// the CSRF token, so it cannot be swapped for another.
    reviewed_version: String,
}

/// POST /ui/secrets/{id}/reviewed — the operator has looked at a
/// client-deposited value and accepts it. Until this happens the policy engine
/// treats the secret like one that does not exist: no auto-approve, no
/// notify-only, every release needs a decision (migration 0007).
async fn mark_reviewed(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<ReviewedForm>,
) -> UiResult<Response> {
    let op = operator(&state, &headers).await?;
    // The version is part of the token's binding: only the page that actually
    // displayed those bytes can produce a token that verifies here.
    check_post(
        &state,
        &headers,
        R_SECRET_VET,
        &id.to_string(),
        &op.subject,
        &form.reviewed_version,
        &form.csrf_token,
    )?;
    let reviewed_version: i32 = form
        .reviewed_version
        .parse()
        .map_err(|_| UiError::bad_request("invalid reviewed version"))?;
    // Already reviewed, gone, or rotated since the reveal: nothing was written
    // and nothing audited, so say so rather than redirecting as if this call
    // did the work — same as the revoke handler.
    if !db::mark_secret_vetted(&state.db, id, reviewed_version, &op.subject).await? {
        return Err(UiError::new(
            StatusCode::CONFLICT,
            "that secret is already reviewed, no longer exists, or has been rotated \
             since you looked at it — open it again to review the current value",
        ));
    }
    Ok(Redirect::to("/ui/secrets").into_response())
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
            let created = db::ui_ext::create_secret_with_version(
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
            if !created {
                // The name was claimed between the lookup above and the
                // insert — a client deposit (`POST /v1/secrets`) racing this
                // form. Nothing was overwritten either way; say so rather than
                // surfacing a unique violation as a 500.
                return Err(UiError::new(
                    StatusCode::CONFLICT,
                    "a secret with that name was just created by someone else. \
                     Reload the page: submitting again would ROTATE it, not create it.",
                ));
            }
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

    /// The review page's headline question — what would vetting switch on —
    /// has to include the rows that release without a human and exclude the
    /// ones that don't, across all three selector shapes.
    #[test]
    fn vetting_activates_only_human_free_policies() {
        let now = Utc::now();
        let row = |outcome: &str, name: Option<&str>, tag: Option<&str>| db::PolicyRow {
            id: Uuid::new_v4(),
            client_name: None,
            secret_name: name.map(str::to_owned),
            secret_tag: tag.map(str::to_owned),
            mechanism: "cli-read".to_owned(),
            outcome: outcome.to_owned(),
            priority: 0,
            origins: serde_json::Value::Array(vec![]),
            methods: vec![],
            path_prefixes: vec![],
            max_ttl_seconds: None,
            max_uses: None,
            not_after: None,
            created_by: "andrew".into(),
            created_at: now,
        };
        let tags = vec!["prod".to_owned()];

        // Selector shapes that match: by name, by tag, and the wildcard row.
        let by_name = row("auto-approve", Some("k"), None);
        let by_tag = row("notify-only", None, Some("prod"));
        let wildcard = row("auto-approve", None, None);
        // ...and ones that must not be listed.
        let other_name = row("auto-approve", Some("other"), None);
        let other_tag = row("auto-approve", None, Some("staging"));
        let needs_human = row("require-approval", None, None);
        let denies = row("deny", None, None);
        let mut expired = row("auto-approve", None, None);
        expired.not_after = Some(now - Duration::hours(1));

        let all = vec![
            by_name.clone(),
            by_tag.clone(),
            wildcard.clone(),
            other_name,
            other_tag,
            needs_human,
            denies,
            expired,
        ];
        let got = policies_activated_by_vetting(&all, "k", &tags, now);
        let ids: Vec<Uuid> = got.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![by_name.id, by_tag.id, wildcard.id]);

        // A secret with no tags loses the tag row but keeps the wildcard.
        let got = policies_activated_by_vetting(&all, "k", &[], now);
        let ids: Vec<Uuid> = got.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![by_name.id, wildcard.id]);
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
