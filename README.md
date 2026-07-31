# keychute

Secrets storage and delivery broker for AI agents, with human approval in the loop
and an explicit, operator-chosen risk tier for every delivery path.

- **Design & project plan:** [docs/DESIGN.md](docs/DESIGN.md)
- **Implementation contract:** [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)

## Status

v1 server-side implementation (design milestones M0–M3) plus packaging:

- `server/` — the `keychute-server` binary: envelope crypto (KEK keyset +
  process-local ephemeral KEK), Postgres store, policy engine, client API
  (idempotent access requests, wait endpoint, grant read with idempotent
  replay, brokered proxy), server-rendered approval UI with CSRF, Pushover
  notifier with request-row outbox, audit log.
- `cli/` — the `keychute` CLI: `keychute curl <url> --secret <name>` to make an
  authenticated HTTP call without ever holding the credential (tier 0 — the
  server attaches it and streams the response back), `keychute request <secret>
  | consumer…` to get a secret out when a consumer genuinely needs the bytes
  (tier 2, human approval in the loop), and `… | keychute store <secret>` to
  deposit a new one (opt-in per client, create-only — it never replaces a
  stored secret).
- `types/` — shared API types.
- `e2e/` — black-box end-to-end suite: each test boots a fresh Postgres
  database, a real server process, a TLS recording upstream, a fake Pushover,
  and drives the REST API, the real approval UI (CSRF flow included), and the
  real CLI binary.
- `charts/keychute/` — the Helm chart; `Dockerfile` + `.github/workflows/` —
  the multi-arch image build.

## Development

Requires Rust (stable) and PostgreSQL 16.

```sh
# unit + store-layer tests (needs a local Postgres; trust auth)
KEYCHUTE_TEST_DB=postgres://postgres@127.0.0.1:5432/postgres cargo test --workspace --exclude keychute-e2e

# e2e: prebuild first (test binaries must not race cargo), then run
cargo build -p keychute-server -p keychute-cli
E2E_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres cargo test -p keychute-e2e -- --test-threads=2
cargo test -p keychute-e2e -- --ignored --test-threads=1   # slow sweeper tests
```

## Deployment

The Helm chart lives in `charts/keychute`; the multi-arch image build and the
chart digest bump are in `.github/workflows/build.yaml`. See DESIGN §7 for how
the two fit together.

```sh
helm lint charts/keychute
helm template charts/keychute
```

Cluster wiring lives in [`werdnum/kube-config`][kube-config]: the ArgoCD
Application and values (`kubernetes/{applications,helm-values}/workloads/keychute/`),
the Postgres database and role, the Keycloak realm client, the Cloudflare Tunnel
hostname, and the internal-CA bundle that clients verify the server with
(published by trust-manager). The `keychute` CLI is baked into the `k8s-agent`
image from this repo's server image, alongside a `keychute` skill documenting
tier-2 use.

Not yet in-tree: the family-assistant integration (see DESIGN §8).

[kube-config]: https://github.com/werdnum/kube-config
