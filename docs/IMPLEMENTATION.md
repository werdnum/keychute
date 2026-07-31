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
- `keychute` CLI (`curl` → wait → proxy → stdout for brokered HTTP;
  `request` → wait → read → stdout for releasing tiers; `store` for deposits).
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
    may_store_secrets: true   # optional, default false: allows POST /v1/secrets
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
  max_deposits_per_hour_per_client: 20   # POST /v1/secrets, per client
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
- `POST /v1/secrets` — client-initiated deposit of a NEW secret (DESIGN
  CUJ 2b). Body:
  ```json
  {
    "name": "my-api-key",
    "value": "<utf8 or base64>",
    "encoding": "utf8",              // default "utf8"
    "description": "provisioned by the agent",
    "max_tier": "brokered",          // default "brokered"
    "injection_kind": "bearer",      // 'bearer' | 'header' | 'basic'; default 'bearer'
    "injection_header": "X-Api-Key"  // header name for 'header', username for 'basic'
  }
  ```
  → `201 {"secret_id": "...", "name": "...", "version": 1}`.
  Guardrails, all server-enforced: the client must have `may_store_secrets` in
  config (else `403 policy-denied`); the endpoint is **create-only**, so an
  existing name is `409 secret-exists` and never a rotation; `max_tier` may not
  exceed the client's own cap (`400`); tags cannot be set by a client (tag
  membership selects policy rows); `429 too-many-deposits` past
  `limits.max_deposits_per_hour_per_client` — counted off the audit log inside
  the deposit's own transaction, behind a per-client advisory lock, so
  concurrent deposits cannot each observe the same pre-deposit count.
  A deposit lands with `operator_vetted = false`, so it can never satisfy a
  standing auto-approve/notify-only row until a human reviews it. Bounds:
  name ≤ 128 bytes of
  `[A-Za-z0-9._-]` (not leading `.`), description ≤ 1 KiB, decoded value ≤
  64 KiB. Writes `secret-created` with `client_name` set and actor
  `client:<name>`, plus a best-effort FYI push. Not idempotent by design — a
  blind retry conflicts rather than silently rotating — so the CLI does not
  retry it.
- `ANY /v1/grants/{id}/proxy/{path...}` — brokered. Query string passthrough.
  The target origin comes from the grant (single-origin grants in v1: a brokered
  request must name exactly one origin). Method+path validated against grant.
  Body streamed up to limit. Response streamed back verbatim, redirects NOT
  followed. Strip-list + header synthesis per DESIGN §4.
- Every error response Keychute generates itself carries
  `X-Keychute-Error: <code>` — the same server-vocabulary code as the body.
  On the proxy path a caller otherwise cannot tell a Keychute `403
  policy-denied` from an upstream's own `403`: same status, and an upstream may
  well answer with the same `{"error": …}` shape. The CLI keys its exit codes
  off this header (a Keychute refusal is exit 3; an upstream 4xx is a
  successful call that returned an error document). The proxy strips the header
  from every upstream response, so an upstream cannot forge one.
- Grant access (read/proxy/wait) always revalidates: client enabled, mechanisms,
  max tiers, not revoked/expired, policy row still live (grant carries
  `not_after` already capped at approval time; revalidation re-checks client and
  secret caps only — policy row deletion does not retro-revoke, revocation does).

Human/UI routes (cookie-less; bearer via `Authorization` header in static mode,
or Envoy-forwarded JWT in oidc mode):

- `GET /` — landing page: pending-decision banner plus counts and links for
  each section, so the bare hostname is a usable entry point. Human-authed like
  the rest of the UI (the counts describe stored secrets and live grants).
  `GET /ui` and `GET /ui/` redirect here.
- `GET /ui/requests` — pending list. `GET /ui/requests/{id}` — approval page.
- `POST /ui/requests/{id}/approve` — form fields: `csrf_token`, optional
  `secret_value` (when secret not stored), `store_secret` checkbox,
  optional `substitute_secret` (also only when the secret is not stored — see
  addendum #20), `ttl_seconds`/`max_uses` overrides (may only narrow the request).
- `POST /ui/requests/{id}/deny`.
- `GET /ui/grants` + `POST /ui/grants/{id}/revoke`.
- `GET /ui/policies` + `POST /ui/policies` (create standing grant row) +
  `POST /ui/policies/{id}/delete`.
- Admin secret management (human-auth too): `POST /ui/secrets` (create/rotate:
  name, value, max_tier, injection template), `GET /ui/secrets`,
  `POST /ui/secrets/{id}/review` (the decision page for a client deposit:
  depositing client, injection template, tier, and which standing policies would
  begin releasing it with no human once vetted — with the plaintext shown only
  on an explicit `reveal=1`, which is what audits `secret-revealed`) and
  `POST /ui/secrets/{id}/reviewed` (lift the unvetted clamp; audits
  `secret-vetted`). A revealed value renders verbatim in a `<pre>` — base64 when
  it is not valid UTF-8 — so what the operator sees is what is stored, not a
  whitespace-collapsed or lossily-decoded rendering of it. The confirmation is
  bound to the displayed version — in the
  CSRF token AND in the `UPDATE ... AND current_version = $2` — so a rotation
  between the two steps cannot vet bytes nobody saw. Both are POST: a URL that
  renders a credential would sit in browser history.
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
  enabled bool, operator_vetted bool default true, created_at, updated_at)` —
  `operator_vetted` is false for a client deposit until an operator reviews it
  (`POST /ui/secrets/{id}/reviewed`); the policy engine clamps an unvetted
  secret to at most `require-approval`, exactly like an absent one.
- `secret_versions(id uuid pk, secret_id fk, version int, ciphertext bytea,
  nonce bytea, wrapped_dek bytea, kek_id text, created_at, created_by_request
  uuid null, unique(secret_id, version))` — append-only; only `wrapped_dek`+
  `kek_id` may be updated (rewrap).
- `secret_tags(secret_id, tag, pk both)`
- `clients(id, name unique, max_tier int, mechanisms text[], auth_kind text,
  api_token_sha256 text null, sa_audience text null, sa_subject text null,
  may_store_secrets bool default false, enabled bool)` — reconciled from config at startup (upsert by name; disable
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
  Indexed on `at`, plus a partial `(client_name, at) WHERE kind =
  'secret-created'` (migration 0008) for the deposit rate cap, which counts
  inside the deposit's transaction while holding that client's lock.

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

## Review addendum — pinned resolutions (Codex round 1)

These override anything above where they conflict.

1. **Ownership on every object operation.** `GET /v1/access-requests/{id}`,
   `/wait`, `POST /v1/grants/{id}/read`, and `/proxy` all require
   `authenticated_client == row.client_name`; mismatch → 404 (not 403 — do not
   confirm existence). Replay reads too.
2. **Unique authn bindings.** Partial unique indexes on
   `clients(api_token_sha256) WHERE api_token_sha256 IS NOT NULL` and
   `clients(sa_audience, sa_subject) WHERE sa_audience IS NOT NULL`. Config
   validation also rejects duplicate token hashes / SA bindings across clients.
3. **TokenReview algorithm.** Send `spec.audiences` = the union of all
   configured client SA audiences. Accept only if `status.authenticated ==
   true`, `status.user.username` exactly equals some client's `sa_subject`, and
   that client's `sa_audience` ∈ `status.audiences` (the intersection the API
   server validated). Exactly one client row may match (guaranteed by #2);
   otherwise reject.
4. **Proxy header contract (exact).** Outbound request is built fresh:
   - Never forwarded from caller: `Host`, `Authorization`, `Proxy-Authorization`,
     `Cookie`, `Set-Cookie`, `Forwarded`, any `X-Forwarded-*`, `X-Real-IP`,
     `X-HTTP-Method-Override`, `X-Method-Override`, `X-Original-URL`,
     `X-Rewrite-URL`, `X-Original-Method`, all RFC hop-by-hop headers
     (`Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`,
     `Transfer-Encoding`, `Upgrade`), every header named in the caller's
     `Connection` value, `Content-Length` (recomputed), `Expect`, and any header
     equal (case-insensitive) to the injection header.
   - Synthesized: `Host` from the approved origin; injection header from the
     template.
   - Injection template validation (at secret create/update time): header kind
     must be a valid token, not in the strip/reserved list above, not `Host`,
     and value placement is always the full header value.
   - Response passthrough strips hop-by-hop headers likewise. Response is
     otherwise verbatim (incl. `Set-Cookie` from upstream — that is upstream
     state for the client, allowed).
5. **Push vocabulary for unknown secrets.** If `secret_name` does not match a
   stored secret at push time, the push says `a not-yet-stored secret` (generic
   label); the name appears only on the approval page. Stored-secret names are
   operator vocabulary and may appear.
6. **Replay window enforced in SQL.** The replay branch requires
   `first_read_at + replay_window >= now()` inside the same transaction,
   plus grant not revoked and `now() < not_after`, plus caller ownership.
   Stale replay rows (outside window) → `Exhausted` (or normal first-use path
   if uses remain).
7. **Plaintext HTTP requires explicit opt-in.** Config gains
   `allow_insecure_http: false` (default). Without TLS config, the server
   refuses to start unless `allow_insecure_http: true`; additionally refuse
   non-loopback binds without TLS unless `allow_insecure_http_non_loopback:
   true` (e2e uses loopback).
8. **Approval checks expiry.** The approve UPDATE includes
   `AND now() < expires_at`. Same for deny.
9. **CSRF.** UI POST protection: (a) if an `Origin` header is present it must
   exactly equal the configured `external_url` origin (or the request's own
   scheme+host when accessed via internal URL — pin: compare against
   `external_url` origin OR `Host`-derived origin, exact match); missing
   `Origin` + present `Sec-Fetch-Site` other than `same-origin`/`none` →
   reject; (b) the form token MACs (route, action id i.e. request/grant/policy
   id, subject, expiry) and is single-purpose. Both required on every POST.
10. **Push dedup key** = client + secret + mechanism + hash of normalized
    constraints (origins, methods, prefixes, ttl, max_uses). Retry cap: after 5
    failed attempts, keep retrying but back off to once per sweep (30s) —
    never abandon a pending undelivered request while it is pending.
11. **Purge lifecycle (sweeper, every 30s).** (a) pending past expiry →
    expired + audit; (b) grants: passthrough payload nulled when [consumed and
    replay window closed] or [expired] or [revoked]; (c) request context
    ciphertext nulled when request reached terminal state more than 24 h ago;
    (d) grant_reads rows older than the replay window keep the row but drop its
    `secret_version_id` pin (`ui_ext::unpin_stale_grant_reads`). The row stays
    as a tombstone and MUST NOT be deleted: `begin_grant_use` already reported
    that idempotency key as `Exhausted`, and deleting the row would let the
    same key burn a fresh use on a multi-use grant and release a newer secret
    version under a key the caller believes is spent. Tombstones are collected
    with their grant (`ON DELETE CASCADE`).
12. **Outbound URL construction.** Build `Url` from the approved origin
    (`https://host[:port]`), then `set_path(...)` and `set_query(...)` on that
    parsed URL. Never string-concat, never `join()`. What `set_path` receives is
    the **decoded** canonical path (the one `prefix_matches` approved and the
    audit row records) with `%` — and only `%` — escaped to `%25` first. Do NOT
    hand it an already-percent-encoded path: `set_path` percent-encodes its
    argument itself, so pre-encoding double-encodes (`/a%20b` → canonical
    `/a b` → `/a%20b` → emitted `/a%2520b`), sending a *different* upstream
    resource than the one approved. The `%25` pre-escape is needed because `%`
    is the one character `set_path` leaves alone: a canonical path may contain
    a literal `%` (raw `/a%2541` canonicalizes to `/a%41`), and emitting that
    bare would give upstream a second decode (`/aA`). Handing over a decoded
    path is safe only because `paths::canonicalize` has already rejected every
    input whose decoded form could change the path's STRUCTURE (`%2F`, `%5C`,
    raw `\`, dot segments, `//`, control characters, non-UTF-8), so `set_path`
    cannot introduce structure `prefix_matches` did not see.
    Origin host normalization: lowercase ASCII, strip trailing dot, reject
    userinfo/IP-with-brackets oddities at parse (already in types Origin);
    ports compared *effective* (443 == None).
13. *(already in config)* `limits.max_proxy_streams_per_client` — enforced via
    `AppState::try_take_slot(client, SlotKind::Proxy)` for the whole
    request/response stream lifetime.
14. **`Cache-Control: no-store` on every secret-bearing response**: grant read,
    proxy responses (add the header to the proxied response in addition to
    upstream's headers — override upstream's value), and all UI pages.
15. **Revalidation rule (final).** At access time re-check: grant not revoked,
    `now() < not_after`, client exists+enabled, mechanism still in client's
    list, tier ≤ client.max_tier, and (if the secret row exists) secret
    enabled + tier ≤ secret.max_tier. Policy-row existence is NOT re-checked
    (grants already carry the policy-capped `not_after`); revocation is the
    retroactive kill switch.
16. **Approval-time storage metadata.** The approval form for a not-yet-stored
    secret with "store" checked requires `max_tier` (default = the tier of the
    requested mechanism — never broader) and optional injection template
    (default bearer). Secret + version creation joins the approval transaction.
17. **Injection kinds.** `bearer` (Authorization: Bearer <secret>), `header`
    (named header, validated per #4), `basic-password` (config stores
    `injection_username`; header = `Authorization: Basic
    base64(username ":" secret)`). Malformed/NUL/CR/LF bytes in the secret for
    header placement → the proxy call fails closed with 502 code
    `bad-credential-encoding` (never sent partially).
18. **Idempotency canonicalization + bounds.** The MAC input is the canonical
    JSON serialization (serde_json with sorted keys — serialize
    `CreateAccessRequest` to `serde_json::Value`, then a canonical writer that
    sorts object keys, no whitespace) of the request body MINUS
    `idempotency_key` and MINUS `context.structured`. The latter carries
    machine-captured environment (the CLI's `ps` snapshot of the invoking
    pipeline) that legitimately differs between two otherwise identical
    invocations, and the only recovery path after a failed grant read is to
    rerun with the same idempotency key — so MACing it would 409 that retry
    and strand an approved grant. Everything deliberately stated stays in,
    `context.reason` included: changing the stated reason under a reused key
    is a different claim about the request and must be detected.
    Bounds enforced at the API: `idempotency_key` ≤ 128
    bytes, `reason` ≤ 4 KiB, `structured` context ≤ 16 KiB serialized,
    constraints lists ≤ 32 entries each. Oversize → 400.
19. **KEK retirement lock.** Every transaction that INSERTs a wrapped DEK takes
    `pg_advisory_xact_lock_shared(hashtext('keychute-kek'))`, and takes it
    BEFORE reading the active KEK: sealing is done by a callback the store
    function runs inside the transaction (`db::SealFn`, or the
    version-numbered closure of `rotate_secret_version`), never by the caller
    beforehand. A caller that sealed first could have its key retired in the
    gap — the zero-reference check would pass while its reference is still
    uncommitted — leaving that row permanently undecryptable. The (admin CLI /
    future) retirement path takes the exclusive form before checking
    zero-references. v1 ships the shared-side discipline in the store layer +
    a `verify_no_references(kek_id)` store function; the operator runbook does
    the rest. Grant passthrough payloads are out of scope, and are the ONLY
    carve-out: they are sealed under the process-local ephemeral KEK, which is
    not part of the keyset and is never retired (`verify_no_references`
    correspondingly does not count them, and their transactions do not take the
    lock). That carve-out is enforced by the type, not by convention —
    `db::PassthroughPayload` has private fields and exactly one constructor,
    `PassthroughPayload::seal(&EphemeralKek, grant_id, value)`, which does the
    ephemeral sealing itself: a keyset-sealed blob cannot be smuggled in, so no
    caller can reintroduce the "seal first, lock later" shape by attaching a
    durable payload to a grant. The read path matches: a passthrough is only
    ever opened with the ephemeral KEK, never by guessing an active keyset key.
20. **Substituting a stored secret at approval time.** When a request names a
    secret Keychute does not hold, the approval page also offers the stored
    secrets that could serve the requested tier (`substitute_secret`, value
    `"<current_version>:<name>"`). Picking one issues the grant against THAT
    secret: `grants.secret_name` is the released name, nothing is stored under
    the name the client asked for, and the `request-approved` audit row carries
    `detail.substituted_for_requested_name` so the two names are both on the
    record. `substitute_secret` is mutually exclusive with `secret_value` /
    `store_secret`, and is rejected outright on the stored-secret form.
    Before releasing, the handler re-checks the chosen row against LIVE state:
    still present, enabled, `current_version` unchanged since the page rendered
    (otherwise the same 409 re-render as the requested name's own state marker,
    `secret_state_marker`), tier ≤ its `max_tier`, and — because the
    request's stored decision was evaluated against a name no rule could match
    — a full re-run of the policy engine for the chosen secret. A `deny` row
    scoped to it (by name or tag) refuses the approval, and the winning row's
    `not_after` caps the grant alongside the request's own cap. That re-run
    uses the EFFECTIVE constraints (the operator's narrowed `ttl_seconds` /
    `max_uses`), not the requested ones: narrowing makes the request a subset
    of more rows, and a tighter row that only now matches is exactly the one
    whose cap must apply.
    The resolved request page reads the released name off the grant rather than
    the request row, so revisiting a substituted approval shows what was
    actually released, plus the name the client asked for.

## Definition of done per module

Unit tests in-crate for: crypto roundtrip/AAD-swap/rewrap/retirement-lock,
policy precedence table, path canonicalization, CSRF token, config parsing.
E2E for the CUJs and security properties. `cargo test --workspace` green,
fmt+clippy clean.
