# Keychute implementation contract (v1)

This document is the working contract for the v1 implementation. `docs/DESIGN.md`
is authoritative for semantics; this file pins the concrete shapes: crate layout,
API surface, DB schema, config format, and coding invariants. When the two
disagree, DESIGN.md wins — flag the discrepancy.

## Scope of v1 (this build)

Milestones M0–M3 server-side, minus cluster wiring:

- Envelope crypto core (KEK keyset file, DEK per version, derived AAD, ephemeral
  process KEK for passthrough payloads, keyed MAC for idempotency keys).
- Postgres schema + store layer.
- Access requests (idempotent create), wait endpoint (long-poll), durable grants,
  single/multi-use read with idempotent replay, brokered proxy with constraint
  enforcement, audit log with write-ahead release events.
- Policy engine (deny-overlap, subset rule, deterministic precedence).
- Approval UI (server-rendered, CSRF, escaping invariants), approval-time secret
  entry (store or passthrough), standing-grant management.
- Notifier trait + Pushover impl + request-row-as-outbox retry sweep. E2E uses a
  fake Pushover HTTP endpoint (configurable base URL).
- Client authn: static API tokens (SHA-256 hash in config) and Kubernetes
  TokenReview (pluggable; e2e uses a fake TokenReview server via configurable URL).
- Human authn: pluggable — `static` mode (bearer token hash + subject, for
  dev/e2e) or `oidc` mode (JWT validation: issuer, audience, signature via JWKS,
  exp/nbf with skew, group/subject allowlist).
- `keychute` CLI (request → wait → read → stdout).
- TLS: rustls listener when cert/key paths configured; plain HTTP otherwise
  (dev/e2e). Production charts always configure TLS.
- Abuse guards: per-client pending-request cap, per-client concurrent wait cap,
  wait lifetime bound, proxy body-size limit and stream deadline, push dedup.

Not in v1: Helm chart, GH Actions image build (stub workflow ok), FA-side code,
notify-digests, per-client token-bucket rate limiting (M5).

## Workspace layout

- `types/` — shared API request/response types, tier & mechanism enums,
  constraint types. No IO. This crate is the API contract between server, CLI,
  and tests. Do not add server-only logic here.
- `server/` — the service binary (`keychute-server`).
  - `src/config.rs` — config file (YAML) + env loading.
  - `src/crypto/` — envelope crypto (see below).
  - `src/db/` — migrations glue + store layer (all SQL lives here).
  - `src/policy/` — policy engine (pure functions over rows; unit-testable).
  - `src/authn/` — client authn (api token, tokenreview) + human authn.
  - `src/api/` — client-facing REST handlers.
  - `src/ui/` — approval pages (maud), CSRF.
  - `src/notify/` — notifier trait, Pushover impl, outbox sweep.
  - `src/proxy.rs` — brokered proxy leg.
  - `src/audit.rs` — audit helpers.
- `cli/` — `keychute` binary.
- `e2e/` — integration test crate (`e2e/tests/*.rs`), harness in `e2e/src`.
- `migrations/` — sqlx migrations, embedded via `sqlx::migrate!("../migrations")`
  from the server crate (path relative to `server/`).

## Coding rules

- **sqlx runtime queries only** (`sqlx::query`, `query_as`, `query_scalar` with
  `.bind()`). No `query!` macros (no compile-time DB dependency).
- **Secret material is typed.** Plaintext secret bytes live in
  `secrecy::SecretBox<[u8]>` (alias `SecretBytes` in `server/src/crypto/mod.rs`)
  or `secrecy::SecretString`. Never `Debug`/`Display` them; never put them in
  errors, logs, or audit rows. `expose_secret()` calls are confined to: crypto
  module internals, the proxy header-injection site, the grant-read response
  writer, and the approval-form ingestion path.
- Application-owned plaintext buffers zeroize on drop (`Zeroizing`).
- All timestamps UTC (`chrono::DateTime<Utc>`), DB `timestamptz`.
- IDs are UUIDv4, exposed as strings.
- Errors: `thiserror` enums in the server; handlers map to a JSON problem shape
  `{"error": {"code": "...", "message": "..."}}`. Messages must never embed
  client-supplied context or secret material.
- Everything async (tokio). No blocking calls in handlers.
- `cargo fmt` clean, `cargo clippy -- -D warnings` clean.

## Config file (YAML, path via `KEYCHUTE_CONFIG`)

```yaml
listen_addr: "127.0.0.1:8443"
external_url: "https://keychute.example.dev"      # used in push links
tls:                       # optional; absent → plain HTTP (dev only)
  cert_path: /etc/keychute/tls/tls.crt
  key_path: /etc/keychute/tls/tls.key
database_url: "postgres://..."                     # env KEYCHUTE_DATABASE_URL overrides
kek_file: /etc/keychute/kek/keyset.json
human_auth:
  mode: static             # or oidc
  static:
    token_sha256: "<hex>"  # bearer token hash
    subject: "andrew"
  oidc:
    issuer: "https://id.example.dev/realms/main"
    audience: "keychute"
    jwks_url: "https://id.example.dev/realms/main/protocol/openid-connect/certs"
    allowed_subjects: ["..."]        # OR:
    allowed_group: "keychute-admins"
    group_claim: "groups"
clients:                   # declarative client provisioning (reconciled at startup)
  - name: family-assistant
    max_tier: trusted-client
    mechanisms: [brokered, autofill]
    auth:
      api_token_sha256: "<hex>"
  - name: k8s-agent
    max_tier: cooperating-client
    mechanisms: [cli-read]
    auth:
      service_account:
        audience: "keychute.example.dev"
        subject: "system:serviceaccount:k8s-agent:k8s-agent"
tokenreview_url: "https://kubernetes.default.svc/apis/authentication.k8s.io/v1/tokenreviews"  # e2e overrides
tokenreview_token_path: null   # bearer for TokenReview calls (in-cluster SA token); null → no auth header
tokenreview_ca_path: null
pushover:
  base_url: "https://api.pushover.net"   # e2e points at fake
  token: "..."           # or token_path / env
  user_key: "..."
limits:
  max_pending_per_client: 10
  max_waits_per_client: 5
  wait_max_seconds: 300
  request_expiry_seconds: 3600
  proxy_max_body_bytes: 10485760
  proxy_stream_deadline_seconds: 300
  replay_window_seconds: 60
```

## KEK file format (`keyset.json`)

```json
{
  "active": "k1",
  "keys": { "k1": "<base64 32 bytes>", "k0": "<base64 32 bytes>" },
  "mac_key": "<base64 32 bytes>"
}
```

`mac_key` is the idempotency-MAC key (never in Postgres).

## Tiers & mechanisms (types crate)

```
Tier: 0 brokered | 1 trusted-client | 2 cooperating-client | 3 direct
  (serde: "brokered", "trusted-client", "cooperating-client", "direct")
Mechanism: "brokered" | "autofill" | "cli-read" | "direct-read"
  mechanism → tier: brokered→0, autofill→1, cli-read→2, direct-read→3
```

Constraints (all optional per mechanism):

```rust
struct Constraints {
    origins: Vec<Origin>,        // scheme=https fixed, host, optional port. For
                                 // brokered: target origins. For autofill: page origins.
    methods: Vec<String>,        // uppercase; empty = deny-all for brokered? NO —
                                 // empty means "unconstrained" ONLY in policy rows;
                                 // a brokered REQUEST must list explicit origins & methods.
    path_prefixes: Vec<String>,  // canonical, segment-boundary matching
    ttl_seconds: u64,
    max_uses: Option<u32>,       // None = unlimited within TTL (brokered);
                                 // releasing tiers (1–3) default 1 and may not exceed 1 in v1
}
```

Path canonicalization: percent-decode once; reject if the decoded path contains
`%`-ambiguity (any encoded `/` i.e. `%2F`/`%2f`, encoded `\`, raw `\`), `.` or
`..` segments, or non-UTF8. Match prefixes at `/` boundaries only. The proxy
forwards exactly the validated canonical path (re-encoded conservatively).

## HTTP API (all under `/v1`, JSON)

Client authn: `Authorization: Bearer <api-token>` or
`Authorization: Bearer <sa-jwt>` (tried as API token hash first, then TokenReview).

- `POST /v1/access-requests` — body:
  ```json
  {
    "idempotency_key": "client-chosen string",
    "secret_name": "my-api-key",
    "mechanism": "cli-read",
    "constraints": { ... },       // as above; ttl_seconds required
    "context": { "reason": "...", "structured": { ...arbitrary json... } }
  }
  ```
  → `201 {"request_id": "...", "state": "pending"}` (or `200` with the same id on
  idempotent retry; `409` if key reused with different payload MAC; `403` on
  policy deny / tier over cap; `201` with `state: "approved"` + `grant_id` when
  policy auto-approves; `429` over pending cap).
  Requesting an unknown secret name is allowed (approval-time entry); the request
  records the name.
- `GET /v1/access-requests/{id}` → state + `grant_id` when approved.
- `GET /v1/access-requests/{id}/wait?timeout_seconds=N` — long-poll; returns as
  soon as resolved or after min(N, wait_max). 200 with state (may still be
  pending). Caller identity must match the request's client.
- `POST /v1/grants/{id}/read` — body `{"idempotency_key": "..."}`. Single logical
  read: atomic accounting + replay within window returns identical plaintext and
  the same `secret_version_id`. → `{"secret": "<utf8 or base64>", "encoding":
  "utf8"|"base64", "secret_version_id": "..."}`. Only for mechanisms cli-read /
  autofill / direct-read. 410 with code `payload-lost` if a passthrough payload
  was lost to restart.
- `ANY /v1/grants/{id}/proxy/{path...}` — brokered. Query string passthrough.
  The target origin comes from the grant (single-origin grants in v1: a brokered
  request must name exactly one origin). Method+path validated against grant.
  Body streamed up to limit. Response streamed back verbatim, redirects NOT
  followed. Strip-list + header synthesis per DESIGN §4.
- Grant access (read/proxy/wait) always revalidates: client enabled, mechanisms,
  max tiers, not revoked/expired, policy row still live (grant carries
  `not_after` already capped at approval time; revalidation re-checks client and
  secret caps only — policy row deletion does not retro-revoke, revocation does).

Human/UI routes (cookie-less; bearer via `Authorization` header in static mode,
or Envoy-forwarded JWT in oidc mode):

- `GET /ui/requests` — pending list. `GET /ui/requests/{id}` — approval page.
- `POST /ui/requests/{id}/approve` — form fields: `csrf_token`, optional
  `secret_value` (when secret not stored), `store_secret` checkbox,
  `ttl_seconds`/`max_uses` overrides (may only narrow the request).
- `POST /ui/requests/{id}/deny`.
- `GET /ui/grants` + `POST /ui/grants/{id}/revoke`.
- `GET /ui/policies` + `POST /ui/policies` (create standing grant row) +
  `POST /ui/policies/{id}/delete`.
- Admin secret management (human-auth too): `POST /ui/secrets` (create/rotate:
  name, value, max_tier, injection template), `GET /ui/secrets`.
- CSRF: session-less double-submit is NOT enough with header auth; since auth is
  a header (no cookies), CSRF risk is minimal, but implement `Origin`/
  `Sec-Fetch-Site` checks on all POSTs + a per-rendered-form token MAC'd with the
  mac_key over (route, subject, expiry). Reject stale (>15 min) tokens.
- All UI responses: `Cache-Control: no-store`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';
  frame-ancestors 'none'; form-action 'self'`.
- All client-supplied context rendered via maud text nodes (auto-escaped) — never
  `PreEscaped` for anything client-derived. The approval page must render the
  server-parsed grant block separately from client context, labelled.

## DB schema (migrations)

Use `uuid` PKs (`gen_random_uuid()` via pgcrypto or app-generated), `timestamptz`.

- `secrets(id, name unique, description, max_tier int, injection_kind text
  ['bearer'|'header'|'basic'], injection_header text null, current_version int,
  enabled bool, created_at, updated_at)`
- `secret_versions(id uuid pk, secret_id fk, version int, ciphertext bytea,
  nonce bytea, wrapped_dek bytea, kek_id text, created_at, created_by_request
  uuid null, unique(secret_id, version))` — append-only; only `wrapped_dek`+
  `kek_id` may be updated (rewrap).
- `secret_tags(secret_id, tag, pk both)`
- `clients(id, name unique, max_tier int, mechanisms text[], auth_kind text,
  api_token_sha256 text null, sa_audience text null, sa_subject text null,
  enabled bool)` — reconciled from config at startup (upsert by name; disable
  rows absent from config).
- `policies(id, client_name text null /*null = any*/, secret_name text null,
  secret_tag text null, mechanism text, outcome text
  ['auto-approve'|'notify-only'|'require-approval'|'deny'], priority int,
  origins jsonb, methods text[], path_prefixes text[], max_ttl_seconds bigint
  null, max_uses int null, not_after timestamptz null, created_by text,
  created_at)` — exactly one of secret_name/secret_tag set (or both null = any).
- `access_requests(id, client_name, secret_name, mechanism, constraints jsonb,
  context_ciphertext bytea null, context_nonce bytea null, context_wrapped_dek
  bytea null, context_kek_id text null, state text, deny_reason text null,
  resolved_by text null, created_at, resolved_at null, expires_at,
  push_delivered_at null, push_attempts int, idem_client text, idem_key text,
  idem_mac bytea, unique(idem_client, idem_key))`
- `grants(id, request_id unique fk, client_name, secret_name, mechanism,
  constraints jsonb, not_after timestamptz, max_uses int null, use_count int,
  revoked bool, passthrough_ciphertext bytea null, passthrough_nonce,
  passthrough_wrapped_dek, passthrough_ephemeral bool, created_at)`
- `grant_reads(grant_id fk, idem_key text, secret_version_id uuid null,
  passthrough bool, first_read_at, pk(grant_id, idem_key))` — replay state.
- `audit_log(id bigserial, at timestamptz, kind text, request_id uuid null,
  grant_id uuid null, client_name text null, secret_name text null,
  secret_version_id uuid null, actor text null, method text null, origin text
  null, path text null, status int null, detail jsonb null)` — append-only.
  `detail` must never contain secret material or freeform client context.

Atomicity requirements (single statements / explicit transactions):

- Grant use: one `UPDATE grants SET use_count = use_count + 1 WHERE id=$1 AND
  NOT revoked AND now() < not_after AND (max_uses IS NULL OR use_count <
  max_uses) RETURNING ...` — replay path: check `grant_reads` first inside the
  same transaction with `SELECT ... FOR UPDATE` on the grant row.
- Approve: transaction { `UPDATE access_requests SET state='approved' WHERE id=$1
  AND state='pending'` (rowcount 1 required) + `INSERT grants` + audit } —
  unique(request_id) backstop.
- Audit write-ahead: the release-attempt audit row commits in the same
  transaction as use-accounting, before plaintext leaves; completion recorded
  after as a second row (kind `release-completed` / `proxy-completed`).

## Crypto module contract (`server/src/crypto`)

```rust
pub struct Keyset { /* active kek id, map id → Kek, mac_key */ }
pub fn load_keyset(path: &Path) -> Result<Keyset>;

pub enum AadContext<'a> {
    SecretVersion { secret_id: Uuid, version: i32 },
    GrantPassthrough { grant_id: Uuid },
    RequestContext { request_id: Uuid },
}
// AAD = "keychute/v1/" || label || "/" || canonical fields. Never stored.

pub struct Sealed { pub ciphertext: Vec<u8>, pub nonce: [u8;24], pub wrapped_dek: Vec<u8>, pub kek_id: String }
impl Keyset {
    pub fn seal(&self, plaintext: &SecretBytes, aad: AadContext) -> Result<Sealed>;
    pub fn open(&self, sealed: &SealedRef, aad: AadContext) -> Result<SecretBytes>;
    pub fn rewrap(&self, wrapped_dek: &[u8], old_kek_id: &str) -> Result<(Vec<u8>, String)>; // to active
    pub fn idem_mac(&self, client: &str, payload_canonical: &[u8]) -> [u8;32];  // HMAC-SHA256, domain-separated
}
pub struct EphemeralKek { /* random at startup, seal/open with GrantPassthrough AAD */ }
```

DEK wrap: XChaCha20-Poly1305 under the KEK with a fresh random 24-byte nonce,
AAD `"keychute/v1/dek-wrap"`; wrapped blob = nonce || ct. Payload encryption:
XChaCha20-Poly1305 under the DEK, fresh nonce, context AAD as above.

## Policy engine contract (`server/src/policy`)

Pure function:

```rust
pub enum Decision { Deny { reason: &'static str }, RequireApproval, NotifyOnly, AutoApprove }
pub fn evaluate(client: &ClientRow, secret: Option<&SecretRow>, secret_tags: &[String],
                req: &RequestedGrant, policies: &[PolicyRow], now: DateTime<Utc>) -> Decision;
```

Order of checks: client enabled → mechanism allowed for client → tier ≤
client.max_tier and (if secret exists) ≤ secret.max_tier (violation ⇒ Deny) →
deny rows on **overlap** → non-deny rows: match only when requested constraints
are a **subset** in every dimension (origins ⊆, methods ⊆, every requested
prefix covered by some row prefix at segment boundary, ttl ≤ max_ttl, uses ≤
max_uses); precedence: client-specific over wildcard, then exact-secret over
tag over wildcard, then higher priority int, then most-restrictive outcome.
No matching row ⇒ RequireApproval. Unknown secret: only RequireApproval or
Deny (never auto-approve a secret that doesn't exist yet).

Overlap rule for deny: scopes intersect if origin sets intersect (or either
side unconstrained), method sets intersect (or unconstrained), and some
requested prefix is prefix-comparable (either direction) with a row prefix
(or either side unconstrained).

## Notifier

```rust
#[async_trait] pub trait Notifier: Send + Sync {
  async fn send(&self, n: &Notification) -> Result<()>;
}
```

Pushover impl posts `{token, user, title, message, url, url_title}` to
`{base_url}/1/messages.json`. Message contains ONLY server vocabulary: client
name, secret name, tier label, mechanism + approval link. Never client context.
Outbox: after insert of a pending require-approval request, attempt push; on
success set `push_delivered_at`. Background sweep every 30s: pending requests
past expiry → mark expired; pending without `push_delivered_at` and attempts <
5 → retry (increment attempts). Dedup: skip push if an identical pending
request (same client, secret, mechanism) was pushed in the last 60s — but the
approval page always shows all pending.

## E2E harness (`e2e`)

Environment via env vars (set by the harness, override in CI):
`E2E_DATABASE_URL` (default `postgres://postgres@127.0.0.1:55432/`), binaries
located via `CARGO_BIN_EXE_*` — e2e depends on server & cli as
`[dev-dependencies]`? NO — binaries: use `env!("CARGO_BIN_EXE_keychute-server")`
requires same-crate bins. Instead the harness builds with
`escargot`-style: just use `cargo build` artifacts at
`target/debug/keychute-server` / `target/debug/keychute` (harness asserts they
exist and are fresh; the e2e crate has a `build.rs`-free helper that runs
`cargo build -p keychute-server -p keychute-cli` once per test binary via
`std::sync::Once`).

Each test: create fresh database (`CREATE DATABASE e2e_<rand>`), write KEK file
+ config YAML to a tempdir, start server child process on a free port, wait for
`/healthz`, run scenario with reqwest / CLI child processes, assert against DB +
audit rows + fake upstream. Fake services in-harness: upstream HTTPS-less HTTP
server (axum) recording requests; fake Pushover recording pushes; fake
TokenReview endpoint.

## Definition of done per module

Unit tests in-crate for: crypto roundtrip/AAD-swap/rewrap/retirement-lock,
policy precedence table, path canonicalization, CSRF token, config parsing.
E2E for the CUJs and security properties. `cargo test --workspace` green,
fmt+clippy clean.
