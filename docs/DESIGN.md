# Keychute — Design & Project Plan

**Status:** Draft for review — not yet approved, no implementation started.

Keychute is a secrets store and *delivery broker* for AI agents. It holds credentials
encrypted in Postgres and releases them — or the *use* of them — to agent-adjacent
clients under an explicit, operator-visible risk model, with human approval in the
loop by default (Pushover push → web approval UI).

It runs as a Rust service in the K3s cluster managed by `werdnum/kube-config`, and
integrates with `werdnum/family-assistant` and the in-cluster `k8s-agent`.

---

## 1. Positioning: why not Infisical / 1Password CLI / Vault

Existing secret managers and the newer "secrets for agents" products enforce a single
posture: the secret never leaves the backend (header-injection proxies), or the secret
is handed to whoever authenticates (env injection, CLI read). Neither matches how
agents actually operate.

Keychute's core idea is **graduated disclosure**: secret handling is *not* limited to
the backend. The service may keep the credential server-side and broker its use, or
release it to cooperating deterministic client code, or — rarely, deliberately — hand
it to an agent directly. None of these is perfectly safe; the point is that **the
security level of every path is explicit, chosen per-secret and per-client by the
operator, and shown to the human at approval time**. The operator makes the risk
assessment, not the tool.

### Delivery tiers

| Tier | Name | Secret visible to | Typical use |
|------|------|-------------------|-------------|
| 0 | `brokered` | Keychute only — client gets a proxy endpoint that attaches the credential | Powerful API tokens; the standard "attach this header" flow |
| 1 | `trusted-client` | Deterministic client code the agent **cannot** subvert (e.g. family-assistant backend code doing secure autofill) | Website passwords via agentic autofill |
| 2 | `cooperating-client` | Deterministic client code the agent **could** subvert (same container, e.g. `keychute` CLI piping to `kubeseal` inside k8s-agent) | Dropping an API key into a SealedSecret without pasting it through an LLM transcript |
| 3 | `direct` | The agent itself (and therefore its LLM provider's logs) | Low-sensitivity secrets where convenience wins |

Every secret has a **maximum tier** (the most permissive delivery it will ever allow),
every client has a **maximum tier** the operator trusts it with, and every release
happens at an explicit tier ≤ both. The approval UI always states the tier in plain
language: *"family-assistant will make HTTPS requests to api.hellofresh.com using this
key; it will not see the key"* vs. *"the k8s-agent CLI will print this secret to
stdout inside the agent's container; the agent can read it"*.

Tier 2 deserves a caveat the UI makes explicit: it is, in a real sense, a
pinky-promise by the agent. The server can verify that the request came from the
authenticated `keychute` CLI under a given identity, and the CLI can best-effort
capture the invoking shell pipeline (walking parent-process cmdlines) to show what
the output is being piped into — but that capture runs inside the agent's container
and is agent-influenceable. The approval UI therefore renders tier-2 context as
*"tagged as coming from the keychute CLI; pipeline (agent-asserted):
`keychute request … | kubeseal …`"* rather than presenting it as verified fact.

---

## 2. Critical user journeys

### CUJ 1 — Brokered HTTP for family-assistant (tier 0)

1. The FA agent needs to call an authenticated API. It invokes an FA tool that asks
   Keychute for a **grant** on secret `example-api-token` with mechanism `brokered`,
   declaring target constraints — an HTTPS origin (scheme fixed to `https`, host,
   optional port) plus methods and path prefix — and a requested TTL. The scheme
   and port are part of the constraint precisely so an approved `api.example.com`
   grant cannot be exercised against `http://` or an alternate service on the
   same host.
2. Keychute matches this against policy. No standing grant → it sends a Pushover
   notification: *"family-assistant requests 1 h of brokered access using
   'Example API token'."* Pushes carry only server-vocabulary metadata — client
   name, secret name, tier — plus the link to the approval page
   (OIDC-protected). The requested target is client-supplied, so it appears
   only on the approval page alongside the rest of the client-asserted input; a
   prompt-injected client must not be able to exfiltrate anything through a
   pre-approval push.
3. I approve, which stores a durable grant. FA's wait resolves with the `grant_id`
   (never the credential).
4. FA makes requests through `POST /v1/grants/{grant_id}/proxy`. Keychute validates
   each request against the grant's constraints, injects the credential according
   to the secret's operator-configured injection template (§5), forwards, and
   streams the response back. **Redirects
   are never followed server-side**: 3xx responses are returned to the client, so a
   redirect target only ever gets the credential if the client re-requests it
   through the proxy and it passes constraint validation itself. Every proxied call
   is audit-logged. The grant expires by TTL and/or request count.

### CUJ 2 — k8s-agent needs a secret for a SealedSecret (tier 2)

1. Inside its container, the agent runs
   `keychute request my-service-api-key --reason "seal into my-service ns" | ./scripts/create-sealed-secret.sh …`.
2. The CLI authenticates (in-cluster: an audience-bound projected service-account
   token; authn is pluggable, §6), creates the access request, and blocks on the
   wait endpoint until it resolves.
3. I get a Pushover push. The approval page shows the requester identity, the reason,
   the tier warning ("the agent can read this from stdout"), and — if the secret is
   **not** yet stored — an input field where I type/paste the secret, with an
   "also store this in Keychute" checkbox (default off). Approval-time entry doubles as the
   ingestion path, so credentials never have to transit an LLM chat to get into the
   system.
4. Approval writes a durable single-use grant. The CLI's wait returns, it fetches
   the plaintext from the grant's read endpoint, writes it to stdout and exits.
   The pipe consumes it. Nothing lands in the agent
   transcript unless the agent deliberately captures it — which is exactly the
   residual risk tier 2 declares.

### CUJ 3 — Secure agentic autofill for family-assistant (tier 1)

1. I pre-approve a **standing grant**: secret `hellofresh-login` may be released to
   client `family-assistant` at tier `trusted-client`, mechanism `autofill`, for
   N days.
2. The FA agent, driving the browser, calls a new deterministic FA tool
   (e.g. `browser_fill_credential(ref, credential="hellofresh-login")`). The tool's
   *backend code* — not the LLM — fetches the password from Keychute (release is
   auto-approved by the standing grant, still audit-logged and optionally
   notify-only pinged), and passes it straight into Playwright's `fill()` on the
   target element. The value never enters the LLM context, tool arguments, or logs.
3. Keychute records the release with the client-supplied context (page URL, field);
   policy can constrain releases to matching origins (e.g. only when the page
   origin is `hellofresh.com`). The origin the client checks and reports is the
   **target element's frame origin** — not the top-level page URL from earlier
   in the flow — verified against a held element handle whose owner frame is
   inspected in the same step as the `fill()`. Element handles detach on
   navigation, so a navigation between check and fill aborts the fill with an
   error rather than retargeting the credential into a document the grant never
   covered; the client never re-resolves a selector between check and fill.

This is "Secure Agentic Autofill" like 1Password's, but without granting an agent
platform access to the real password-manager account.

---

## 3. Threat model

**In scope**

- The agent's LLM provider logging everything the model sees (the original
  motivation: don't paste credentials into Claude Code / codex).
- A prompt-injected or misbehaving agent trying to exfiltrate secrets: requesting
  secrets it shouldn't, lying about purpose, requesting a more permissive tier,
  or (tier 2) reading what deterministic code in its own container handles.
- Confused-deputy attacks: one client requesting on behalf of/impersonating another.
- Database compromise: Postgres backups, disk, or a read of the DB must not yield
  plaintext secrets (application-level encryption; the DB never sees plaintext).
- Replay/abuse of approved grants beyond their constraints (host, path, TTL, count).

**Explicitly out of scope / accepted residual risk**

- A fully compromised Keychute *process* (it holds the KEK in memory).
- Tier 2: the agent has root in its own container; it can `strace` the CLI or read
  the pipe. The tier exists to remove the *default* leak (LLM transcript), not to
  stop a determined malicious agent.
- Tier 1 subversion via side channels the client fails to close (e.g. the agent
  screenshotting a password it just autofilled before the page masks it). Client
  integrations must document their containment story; see §8.
- Verifying that client code actually *is* the deterministic code it claims to be.
  The client-authn credential is the binding: the operator issues a shared secret
  (API token or SA identity) to a specific deployment and records "this credential
  is client `family-assistant`, tier X". Keychute's responsibility ends at
  authenticating that credential; that it really lives only in the intended
  deployment is operator configuration, not something Keychute can check (see §6,
  "mechanism honesty").

---

## 4. Architecture

```
                        ┌───────────────────────────── Keychute (Rust, ns keychute) ─┐
  Pushover  ◄───────────┤  notifier                                                  │
                        │                                                            │
  Browser (me) ──OIDC──►│  approval web UI  ──┐                                      │
                        │                     ├── policy engine ── release engine    │
  family-assistant ────►│  client API (REST + SSE)                 │        │        │
  k8s-agent CLI ───────►│    │                                     │        ▼        │
                        │    └── TokenReview / API-key authn   audit log  crypto     │
                        │                                          │      (KEK+DEK)  │
                        └──────────────────────────────────────────┼─────────────────┘
                                                                   ▼
                                                    Postgres (storage-cluster,
                                                    ciphertext only)
```

One binary, several logical components:

- **Client API** (`/v1/…`): create access requests; optionally block on a wait
  endpoint (long-poll/SSE) until resolution; exercise grants through server-side
  access endpoints — `read` for releasing tiers, `proxy` for brokered. Authn per §6.
- **Approval UI**: minimal server-rendered (or tiny static SPA) pages behind
  Envoy Gateway OIDC (`id.andrewgarrett.dev` Keycloak, the cluster's standard
  `SecurityPolicy` pattern). Shows request context verbatim, tier in plain language,
  secret-entry form for not-yet-stored secrets, and standing-grant management.
- **Policy engine**: evaluates (client, secret, mechanism/tier, constraints,
  context) → `auto-approve` / `notify-only` / `require-approval` / `deny`.
- **Notifier**: Pushover, using the cluster's existing convention (secret with
  `token` + `user_key`, same as alertmanager and sudo-service). Pluggable trait so
  ntfy/webhook can be added later. Delivery is recorded on the request row, and a
  retry loop plus a startup sweep re-send pushes for pending requests without a
  recorded delivery — the request row *is* the outbox, no separate queue — while
  dedup applies only to recorded deliveries, so a failed push cannot leave a
  pending request the operator never hears about.
- **Release engine**: serves grant access — brokered proxying with constraint
  checks, or plaintext reads with TTL/use-count enforcement (single-use by default
  for releasing tiers). Proxy validation operates on the canonical decoded path —
  ambiguous encoded separators and dot-segments are rejected outright, and exactly
  the validated representation is forwarded — and the forwarded
  `Host`/`:authority` and hop-by-hop headers are synthesized from the approved
  origin, never taken from the caller (a caller-supplied authority could route the
  credential to a different virtual host behind the same wildcard certificate).
  Inbound authentication — the caller's Keychute API token or SA token — and any
  gateway cookies are consumed at the API boundary and never copied into the
  outbound request, so the upstream service never sees credentials that could
  impersonate the client back to Keychute. Remaining caller headers are forwarded
  minus a strip-list covering the routing-override family
  (`X-HTTP-Method-Override`, `X-Original-URL`, `X-Rewrite-URL` and kin) and any
  header colliding with the injection template; an upstream that honors some
  other bespoke routing header is beyond what a proxy can police — tier-0
  constraints assume the upstream routes by method and URL. Path-prefix
  constraints match only at `/` segment boundaries: `/v1/account` covers
  `/v1/account` and `/v1/account/…`, never `/v1/account-delete`.
- **Crypto**: envelope encryption (§5).
- **Audit log**: append-only record of every request, decision, and release/use.

**Approvals are durable state; delivery is pull.** An approval does nothing but
write a grant row — nothing is delivered over the approval or wait channel itself.
The wait endpoint is a pure convenience; a client can equally poll, crash and
retry, or come back later, then access the grant through ordinary server-side
endpoints (`…/read` or `…/proxy`) that enforce TTL and use counts idempotently at
access time. This keeps the request/grant/delivery model independent of connection
lifetime and of Kubernetes: k8s contributes one pluggable authn method
(TokenReview) and the deployment substrate, nothing in the protocol. (Deliberate
departure from sudo-service's output-in-a-short-TTL-Secret pattern, which couples
result delivery to cluster primitives.)

### Rust stack (proposed)

- `axum` + `tokio` + `tower` (HTTP, SSE, middleware), `hyper`/`reqwest` for the
  outbound proxy leg.
- `sqlx` (compile-time-checked queries, Postgres, TLS).
- `chacha20poly1305` (XChaCha20-Poly1305 AEAD), `zeroize` + `secrecy` for in-memory
  hygiene, `rand` (OS RNG) for DEKs/nonces.
- `askama` or `maud` for the approval pages (server-rendered keeps the UI in the
  same trust domain and avoids a JS supply chain for a security-critical page).
- `tracing` with a redaction layer — secret material must be typed (`SecretBox`) so
  it *cannot* be `Debug`-formatted into logs.
- `utoipa` for an OpenAPI spec the FA integration and CLI are generated/checked
  against.

The CLI (`keychute`) is a small subcommand binary from the same workspace,
distributed the way the `sudo-service` CLI is (fetched by pinned ref into the
k8s-agent image).

---

## 5. Cryptography & storage

**Envelope encryption, ciphertext-only database.**

- The **KEK file** (a Kubernetes Secret created via the repo's sealed-secrets
  workflow, mounted as a file; Postgres never sees it) holds a small **keyset**:
  `kek_id → 32-byte key`, exactly one marked active. Every wrapped DEK records
  the `kek_id` that wrapped it.
- Each secret *version* gets a fresh random **DEK**; plaintext is encrypted with
  XChaCha20-Poly1305 under the DEK; the DEK is wrapped under the KEK. AAD binds
  ciphertext to `(secret_id, version)` so rows can't be swapped or replayed across
  secrets — and the AAD is never stored: it is reconstructed canonically from the
  row's queried `secret_id` and `version` at decrypt time, so ciphertext moved to
  another row fails AEAD verification instead of decrypting under a relocated
  stored context.
- KEK rotation = add the new key to the keyset, mark it active, rewrap rows to it
  (cheap — no payload re-encryption, each row update atomic), then retire the old
  key once no row references its `kek_id`. Retirement serializes with ciphertext
  writers: the zero-reference check and key removal run under an advisory lock
  that every wrapped-DEK writer holds in shared mode, so an in-flight write that
  selected the old key cannot commit after retirement declares it unreferenced.
  Because both keys coexist in the file
  during rotation and every row names its wrapping key, a crash at any point
  leaves every secret decryptable on restart. Secret rotation = new version row;
  old versions retained (visible in audit trail) until purged — and never purged
  while referenced by live idempotency state or an unexpired grant, so a pinned
  replay can always return its promised plaintext.
- Plaintext exists only transiently in Keychute memory during a release or proxy
  call, and is never logged, never in error messages, never in the DB (enforced
  by types, reviewed as an invariant). Application-owned buffers zeroize on drop;
  the copies the HTTP and TLS stacks unavoidably make (header values in
  `reqwest`/`hyper`, response and TLS buffers) cannot be zeroized from
  application code, so beyond our own buffers the guarantee is explicitly
  best-effort short-lived process memory, not provable erasure.
- The database is the existing Zalando `storage-cluster` (PG 15, Patroni, daily
  logical backups). Backups therefore contain ciphertext only — losing the KEK
  Secret loses the data, so the KEK's sealed form in git plus the sealed-secrets
  controller key is the recovery chain. This is documented in the runbook.

A dedicated `postgresql` CR is possible (the `lake-system` precedent) but overkill;
the ciphertext-only design removes the main reason to isolate.

### Data model (first cut)

- `secrets` — id, name, description, max_tier, created/updated, current_version,
  and an operator-managed **injection template** for brokered use: how the
  credential is placed on proxied requests (default
  `Authorization: Bearer {secret}`; alternatively a named custom header or Basic
  auth — query-parameter placement is deliberately unsupported, since URLs land
  in upstream access logs, traces, and client error values, which would break the
  never-logged invariant). Injection placement is never taken from the
  requesting client — an agent that could choose the header could smuggle the
  secret into a field the target echoes back.
- `secret_tags` — (secret_id, tag) associations backing tag-scoped policy rows.
  Tag membership is evaluated at request time, so re-tagging a secret
  immediately changes which policies match it.
- `secret_versions` — secret_id, version, ciphertext, nonce, wrapped_dek,
  created_by (approval that ingested it). No stored AAD — it is derived from
  the queried key columns (§ crypto above). Rows are **append-only**: rotation
  inserts a new version, and nothing ever rewrites the ciphertext behind an
  existing `secret_version_id` — pinned replays and audit records depend on that
  immutability. The one in-place update is the KEK rewrap of `wrapped_dek`,
  which changes the wrapping, never the payload.
- `clients` — id, name (`family-assistant`, `k8s-agent`), authn binding (SA
  audience+subject, or API-key hash), max_tier, allowed mechanisms, enabled.
  Client rows are provisioned **declaratively**: a config file (Helm values →
  mounted config) lists each client's name, tier, and authn binding and is
  reconciled at startup, so a fresh deployment has its first client identities
  without imperative bootstrap or direct DB edits. API tokens are generated
  out-of-band by the operator; only their hashes appear in config (a hash of a
  high-entropy token is safe to commit).
- `policies` — (client, secret | secret-tag) → mechanism, tier, constraints
  (HTTPS origins, methods, path prefixes, autofill page origin), outcome
  (`auto-approve` / `notify-only` / `require-approval` / `deny`), expiry.
  Standing grants (CUJ 3 pre-approval) are rows here with an expiry, created from
  the approval UI. Resolution over overlapping rows is deterministic and total:
  `deny` overrides any other matching outcome, and deny rows match on
  **overlap**, not subset — a requested grant whose usable scope intersects a
  denied scope is rejected outright, since a broader grant would implicitly
  contain the denied region (re-request with a narrower scope if the remainder
  was wanted); otherwise rows are ordered
  lexicographically by specificity — client dimension first (specific client
  over wildcard), then secret dimension (exact secret over tag) — then by
  explicit integer priority, and a residual tie resolves to the most restrictive
  matching outcome (`require-approval` over `notify-only` over `auto-approve`),
  so no pair of rows is incomparable and ambiguity can never widen access. A row
  only yields its non-approval outcome when the requested constraints are a
  **subset** of the row's across *every* dimension — origins (HTTPS target or
  autofill frame origin) as well as methods, path prefix, TTL, and use limit; a
  request broader than every matching row falls through to `require-approval` —
  a narrowly pre-approved client cannot silently obtain a wider grant.
- `access_requests` — client, secret, requested mechanism+tier+constraints,
  client-supplied context (freeform + structured), state
  (`pending`/`approved`/`denied`/`expired`), resolved_by, timestamps.
  Client-supplied context is **encrypted at rest** under the same envelope
  machinery as secret payloads: a tier-2/3 client may have credential bytes in a
  reason or script source, and context must not become a plaintext side channel
  into the DB and its backups. It is decrypted only to render the approval page,
  never copied into plaintext audit rows, and purged with the request. Requested
  **constraints** (origins, methods, path prefixes) and the per-call paths in
  the audit log are deliberately *not* encrypted: the server must evaluate,
  index, and display them, so they are structural metadata, and the
  ciphertext-only guarantee is explicitly scoped to secret payloads and
  freeform context. A URL is not a place for a secret — that is already true
  end-to-end (upstream access logs see it too), and the operator sees every
  constraint verbatim in the approval UI. Creation is idempotent: the client
  supplies a creation idempotency key, and a retry after a lost response
  returns the original request id instead of minting a second pending request
  (and a second push). The key is bound to the authenticated client and a
  domain-separated keyed MAC of the normalized request payload (MAC key held in
  the KEK file, never in Postgres — a plain hash would hand a database reader an
  offline guessing oracle for low-entropy values embedded in context); reuse
  with a different payload is rejected rather than silently returning some
  other request's id.
- `grants` — issued capability: request_id, constraints, TTL, max_uses, use_count,
  revoked. (One-shot releases are grants with max_uses = 1.) A passthrough secret
  entered at approval time but not stored is encrypted and attached to its grant,
  and purged when the grant is consumed or expires. "Single-use" means one
  *logical* read: the first read binds the grant to a client-supplied idempotency
  key, and retries with the same key within a short replay window return the same
  plaintext — otherwise a connection lost between the use-count increment and
  delivery would strand an approved grant. The first use persists the resolved
  `secret_version_id` in the idempotency state and replays decrypt exactly that
  version, so a rotation during the window cannot leak a second version through
  one grant. The window closing (or the TTL) is what purges the payload. A grant is not a transferable bearer capability: every
  grant operation — `read`, `proxy`, and idempotent replay — authorizes the
  caller against the client on the originating access request, so a leaked
  `grant_id` is useless to any other client identity. A grant issued under a
  standing policy row also expires no later than that row does — a request made
  minutes before a policy lapses cannot extend access past it. Every access
  additionally revalidates current state — client enabled, secret and client max
  tiers, allowed mechanism — so tightening a cap or disabling a client takes
  effect immediately for already-issued grants rather than waiting for their
  expiry. Every grant use — single- or multi-use — is accounted atomically: the
  expiry/revocation check, idempotency-key binding (where applicable), and the
  `use_count < max_uses` increment happen in one conditional
  `UPDATE … RETURNING`, so concurrent accesses can neither exceed the approved
  count nor both be treated as the first read. A same-key replay is recognized
  inside that same atomic step and returns the pinned payload **without** a
  further increment — replay is the one exception to `use_count < max_uses`,
  bounded by the replay window, and it still revalidates caller, expiry, and
  revocation. The `pending → approved`
  transition and grant insertion likewise happen in one transaction, with a
  conditional state update and a unique constraint on `grants.request_id` — a
  double-submitted approval, or an approval racing expiry, cannot mint two
  grants or resurrect an expired request.
- `audit_log` — append-only: every request, decision, release, and each individual
  proxied call (method, host, path, status — never bodies or credentials). Each
  release or proxy event records the immutable identifier of the payload
  actually decrypted — the `secret_version_id`, or the grant-scoped passthrough
  payload id for approval-time-entered secrets that were not stored — so
  incident response can tell exactly which credential was exposed even across
  rotations. Ordering is write-ahead: the release-attempt event commits
  atomically with the use-accounting update *before* plaintext delivery or
  proxy forwarding, with completion status recorded afterwards — a crash
  mid-release can leave an attempt without a completion, never a release
  without a record.

---

## 6. Policy & approval model

The user-visible question an approval answers has two parts, and policy treats them
separately:

1. **The thing being done, minus mechanism** — *"family-assistant wants to log into
   HelloFresh"*. Matched against standing grants and per-secret rules. Recency
   ("you approved a similar request minutes ago") is surfaced to the approver as
   advisory context only — it never produces an automatic release, which keeps
   the inherently fuzzy notion of "same intent" out of the enforcement path.
2. **The mechanism / tier** — *"…and it will handle the password with deterministic
   autofill code (tier 1)"*. Matched against the secret's max tier and the client's
   max tier.

Outcomes: `deny` (silent or with reason), `require-approval` (push + wait, with a
timeout after which the request expires — sudo-service uses 1 h), `notify-only`
(release proceeds, I get an FYI push — right for standing-grant autofill),
`auto-approve` (silent, audit-logged; for the lowest-stakes cases).

**Client-supplied context** rides with every request and is rendered verbatim (and
clearly labelled as *client-asserted, unverified*) in the approval UI. Verbatim
means faithful, not raw: context is always contextually escaped and rendered
text-only, as an explicit invariant rather than a template implementation detail —
it originates from a possibly prompt-injected agent, and markup executing on the
approval origin would be script injection into the exact page that grants
authority. The context includes: a freeform
"reason", plus structured fields the integration fills in — for FA, the conversation
snippet or the `execute_script` source that triggered the need; for the CLI, the
`--reason` flag, the requesting identity, and the best-effort shell-pipeline
capture (§1, tier-2 caveat). Rendering the actual script that
will consume the secret is a first-class goal of the UI.

Separately from that untrusted context, the approval page always renders the
**server-parsed grant** — normalized origin, methods, path prefix, TTL, use
limit, tier — as the authoritative "what you are approving" block. The operator
approves what the server will enforce, never the client's description of it; a
prompt-injected client that narrates a narrow action while requesting a broad
grant is thereby visible.

### Where enforcement lives — server, client, or both?

**Both, with a clean split** (this resolves the open question in the project brief):

- **The server is authoritative for release decisions**: whether a secret leaves,
  at what tier, to which authenticated client, under what constraints, and it alone
  enforces tier-0 constraints (it proxies the traffic). Nothing a client says can
  raise a tier above the secret's or client's maximum.
- **The client is responsible for containment after delivery**, and that
  responsibility is exactly what the tier label encodes. Keychute cannot verify that
  `family-assistant` really pipes the password into Playwright rather than into the
  LLM context — that's the **mechanism-honesty problem**, and it's answered by
  operator judgement, not protocol: registering a client at tier 1 *is* the
  operator's statement that they trust that deployment's deterministic code.
  Client-side policy (e.g. FA's own tool-policy `confirm` gates) can add friction on
  top but is never load-bearing for Keychute's guarantees.

### Authentication

- **Machine clients** authenticate with one of two equivalent, pluggable methods,
  either way resolving to a `clients` row carrying the name and tier:
  - **Static API tokens** (hash stored server-side): the operator generates a
    token, drops it into the client's environment (e.g. family-assistant's
    config), and records "this token is client `family-assistant`, tier 1". No
    Kubernetes dependency in the protocol — though today every machine client is
    in-cluster and reaches the internal TLS service directly; an out-of-cluster
    client would additionally need a separately routed machine hostname that
    bypasses the human OIDC gateway, which is deferred until such a client
    exists.
  - **Audience-bound projected service-account tokens**
    (`audience: keychute.andrewgarrett.dev`) validated via TokenReview —
    convenient for in-cluster clients like k8s-agent (no secret distribution; the
    pod identity comes with the token), following sudo-service.
- **Humans** (approval UI): Envoy Gateway `SecurityPolicy` OIDC against Keycloak
  with `forwardAccessToken` enabled, so Keychute receives the JWT and validates it
  itself (issuer, audience, signature, and lifetime — `exp`/`nbf` with bounded
  clock skew) rather than trusting proxy headers; the
  validated identity is what the audit log records as the approver.
  Authentication alone never suffices: all human routes additionally require an
  **authorization allowlist** — membership of a configured operator group claim
  (the sudo-service `adminGroup` pattern) or an explicit subject list — since the
  Keycloak realm admits principals who must not approve releases. Approval and
  standing-grant mutations are non-GET and carry application-level CSRF
  protection (per-session token plus `Origin`/Fetch-Metadata checks) — an
  authenticated gateway session alone never proves the operator initiated the
  action, since the gateway attaches the operator's token to whatever their
  browser sends. Human pages are served with
  `Content-Security-Policy: frame-ancestors 'none'` (plus `X-Frame-Options:
  DENY`) so an authenticated approval page cannot be clickjacked from a framing
  site, and — like every endpoint that returns secret material — with
  `Cache-Control: no-store`, so transient rendering never leaves a plaintext
  copy in a browser or intermediary cache. Cluster-
  internal client API routes bypass OIDC (the sudo-service shape: internal service
  URL for machines, OIDC-fronted external URL for me).

---

## 7. Deployment (kube-config)

Follows the sudo-service shape: **source + Helm chart live in `werdnum/keychute`**,
cluster wiring lives in kube-config.

In `werdnum/keychute`:

- Rust workspace: `server/`, `cli/`, shared `types/` crate; `charts/keychute/`.
- GitHub Actions: build `linux/arm64` image → `ghcr.io/werdnum/keychute`
  (multi-stage Dockerfile, static-ish binary on `debian-slim`/`distroless`,
  non-root), push by digest, bump the chart's default image digest — mirroring the
  kube-config `containers/*` workflows and the sudo-service chart-bump flow.

In `werdnum/kube-config` (a later PR, once the service exists):

- `kubernetes/applications/workloads/keychute.yaml` — multi-source Application
  (chart from keychute repo + `$values` + sealed secrets dir), `CreateNamespace=true`,
  `ServerSideApply=true`, auto-sync.
- `storage-cluster/postgresql.yaml`: add `keychute: keychute.keychute` to
  `databases` and `keychute.keychute: []` to `users` — the operator drops the
  credentials Secret into the `keychute` namespace (cross-namespace secrets are
  already enabled).
- Sealed secrets: `keychute-kek` (the master key), `keychute-pushover`
  (`token`/`user_key`, cluster convention).
- Ingress `keychute.andrewgarrett.dev` (nginx class, `letsencrypt-prod`). In this
  cluster Ingresses are materialized as Envoy Gateway HTTPRoutes (generated name
  `<ingress>-<host-with-dashes>`), and the OIDC `SecurityPolicy` targets that
  HTTPRoute — the exact shape of the existing `oidc-security-policy.yaml` examples
  (ansible-drift-ui, notes, webslicer). Because the backend refuses plaintext,
  the gateway-to-service hop needs explicit backend TLS (Gateway API
  `BackendTLSPolicy` naming the service DNS name, with the internal CA bundle
  available in the gateway namespace). Optional Cloudflare-tunnel exposure so
  Pushover links work away from home (tunnel hostname + external-dns target
  annotation, per repo docs) — with the boundary stated honestly and in full:
  the tunnel makes Cloudflare a TLS-terminating party for *all* approval
  traffic, not just typed secrets — it can observe the operator's gateway
  session cookie, CSRF token, and decrypted client context, and a party in that
  position could in principle forge or modify an approval. Using the tunnel is
  therefore an explicit decision to trust Cloudflare with approval authority
  and secret-bearing page content alike — the same trust this cluster already
  extends to Cloudflare Access on every tunneled service, sudo-service
  approvals included. The Tailscale ingress remains the end-to-end alternative
  for anyone declining that trust, and is the recommended route for
  approval-time secret entry either way.
- The chart binds the Keychute ServiceAccount to `system:auth-delegator`
  (ClusterRoleBinding) so the server may create `TokenReview`s — without it every
  SA-token authn attempt is rejected by the API server.
- Internal clients use `https://keychute.keychute.svc.cluster.local` with a
  certificate from a **cluster-internal cert-manager CA issuer** served by the
  Rust process (rustls) — public CAs cannot issue for `*.svc.cluster.local` —
  and plaintext HTTP is not offered, since static API tokens and tier-1/2
  plaintext reads transit this connection and the cluster network is not in the
  trusted base. The CA bundle (public material only) is fanned out to client
  namespaces with the existing reflector pattern and configured explicitly:
  mounted and referenced in family-assistant's config, and a `--ca-bundle`/env
  path for the CLI baked into the k8s-agent image.
- k8s-agent: add the `keychute` CLI to the image (renovate-pinned ref, like the
  sudo-service CLI), and a projected token volume with
  `audience: keychute.andrewgarrett.dev`.
- Namespace file with goldilocks labels; `ghcr-secret` imagePullSecret (conftest
  enforces it); pgpool is available if connection pooling ever matters.

---

## 8. family-assistant integration (later PRs in that repo)

Research findings that shape this (all verified against the current tree):

- FA has **no Pushover** and its own notification stack (VAPID/APNs) — Keychute
  does its own notifications; FA doesn't need to relay approvals.
- FA already has a durable HITL `ConfirmationService`, but Keychute approvals are
  **operator-level, not chat-user-level** — they stay in Keychute. FA's per-tool
  `confirm` policy can still be layered on specific tools as chat-side friction.
- FA has an `ApiBackend` protocol (`services/api_backend.py`) that injects bearer
  tokens and never logs them — the natural seam for CUJ 1: a
  `KeychuteBrokeredBackend` that sends requests to the grant proxy instead of the
  target, or a standalone `authenticated_http_request` tool that manages
  grant acquisition + proxying. Decision deferred to the FA-side design.
- FA has **no generic secrets abstraction** — Keychute's client becomes the first,
  a small `KeychuteClient` service class (static API token from FA's config/env,
  in-cluster URL).
- Autofill: today `browser_fill` takes its text from LLM-generated arguments.
  CUJ 3 needs a new deterministic path — `browser_fill_credential(ref,
  credential_name)` — whose implementation fetches from Keychute and calls
  Playwright `fill()` directly. Containment obligations for tier 1: the value never
  enters tool results or logs; fill only into password-type inputs (or
  operator-overridden per credential); and subsequent `browser_snapshot` /
  `browser_extract` / screenshots must mask the filled field's value, since the
  agent could otherwise read it back off the page. That masking work is part of the
  integration, not optional. And masking alone is insufficient while an
  arbitrary-JS path exists: `browser_exec` (or any raw script evaluation) can
  read `document.querySelector(…).value` directly, so from
  `browser_fill_credential` until the next navigation or form submission the
  integration must withhold script-evaluation tools from the agent. A profile
  that keeps raw JS available while a credential is live does not get tier-1
  treatment — Keychute classifies the mechanism as tier 2 for that client and
  the approval UI says so. (`browser_request_handoff` remains the fallback for
  sites where masking can't be made sound.)
- Context enrichment: when a Keychute request originates inside `execute_script`
  (the Monty sandbox), FA attaches the script source as structured context so the
  approval UI can show me the exact code that will use the access.

---

## 9. Milestones

Each milestone is independently testable and delivers something usable; no
calendar estimates.

- **M0 — Skeleton & crypto core.** Rust workspace, CI (fmt/clippy/test, ARM64 image
  build), migrations, envelope-encryption module with KEK-file loading and
  rotation-rewrap, `secrets` CRUD and append-only `secret_versions` behind an
  admin API that is
  **loopback/test-only in this milestone** — nothing network-reachable is
  deployed until M1's authn and TLS exist. Property tests on the crypto seams;
  no network delivery yet.
- **M1 — CUJ 2 end-to-end (CLI + approval).** Access requests, wait endpoint,
  Pushover notifier, approval UI with OIDC, approval-time secret entry
  (store-or-passthrough), durable grants with a single-use read endpoint
  including grant TTL and an expiry purge (a passthrough payload must not outlive
  its grant, so this cannot defer to a later milestone), audit log, client authn
  (API tokens + TokenReview, clients provisioned declaratively from config),
  `keychute` CLI, and a minimal abuse guard — a
  per-client cap on open pending requests and on concurrent wait connections
  (bounded stream lifetimes, cleanup on disconnect), plus dedup/throttling of
  Pushover notifications for repeated identical requests — since M1 is deployed and the
  threat model already assumes prompt-injected clients (full per-client rate
  limiting remains M5). Deployed to the
  cluster; k8s-agent image gains the CLI. *This is the first real value: agents stop
  needing credentials pasted into transcripts.*
- **M2 — Policy engine & standing grants.** Policy rows, outcomes
  (auto/notify/approve/deny), standing-grant creation and management in the UI,
  grant TTL/max-use/revocation, notify-only pushes.
- **M3 — CUJ 1 brokered proxy + FA integration.** Grant proxy endpoint with
  host/method/path constraint enforcement and per-call audit; FA `KeychuteClient`
  + brokered HTTP tool; script-source context attachment. Ships with the
  proxy-side abuse bounds (per-client concurrent proxy streams, body size
  limits, stream deadlines, disconnect cleanup — the M1 wait-cap logic applied
  to the proxy path), since an auto-approved client could otherwise hold
  unbounded slow streams open.
- **M4 — CUJ 3 secure autofill.** `autofill` mechanism + origin constraints
  server-side; FA `browser_fill_credential` with the masking/containment work in
  the browser tools.
- **M5 — Hardening.** Rate limits per client, KEK rotation runbook, `notify-only`
  digests, threat-model review against the implementation, docs (user + operator).

---

## 10. Open questions for review

1. **FA request UX for tier-0 grants**: grants being durable, both styles are cheap
   on the Keychute side — the FA tool call can block on the wait endpoint with a
   generous timeout, or return "pending" and re-check the request later. I lean
   *blocking* for v1, with pending/re-check in M3 if it chafes.
2. **Notify-only for autofill**: should every standing-grant autofill release ping
   Pushover (auditable but noisy), or only log? Proposed default: notify-only for
   the first release per grant per day.
3. **Proxy response handling** (CUJ 1): responses stream back to FA unmodified.
   Some APIs echo credentials in responses (rare). Do we want optional response
   redaction rules per secret, or accept as residual risk for v1? Proposed: accept
   and document.
4. **Cloudflare tunnel exposure**: approval pages need to be reachable when I'm
   away for Pushover links to be useful. Standard tunnel + Cloudflare Access +
   Keycloak OIDC stacking, same as sudo-service — confirm that's the intent.
