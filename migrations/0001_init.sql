-- Keychute initial schema. Semantics: docs/DESIGN.md §5, shapes pinned in
-- docs/IMPLEMENTATION.md §"DB schema (migrations)".

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    max_tier int NOT NULL,
    injection_kind text NOT NULL DEFAULT 'bearer'
        CHECK (injection_kind IN ('bearer', 'header', 'basic')),
    injection_header text,
    current_version int NOT NULL DEFAULT 0,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only; only wrapped_dek + kek_id may be updated in place (KEK rewrap).
CREATE TABLE secret_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version int NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_dek bytea NOT NULL,
    kek_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by_request uuid,
    UNIQUE (secret_id, version)
);

CREATE TABLE secret_tags (
    secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    tag text NOT NULL,
    PRIMARY KEY (secret_id, tag)
);

-- Reconciled from config at startup (upsert by name; disable rows absent
-- from config).
CREATE TABLE clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    max_tier int NOT NULL,
    mechanisms text[] NOT NULL DEFAULT '{}',
    auth_kind text NOT NULL,
    api_token_sha256 text,
    sa_audience text,
    sa_subject text,
    enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_name text,          -- null = any client
    secret_name text,          -- at most one of secret_name / secret_tag set
    secret_tag text,
    mechanism text NOT NULL,
    outcome text NOT NULL
        CHECK (outcome IN ('auto-approve', 'notify-only', 'require-approval', 'deny')),
    priority int NOT NULL DEFAULT 0,
    origins jsonb NOT NULL DEFAULT '[]'::jsonb,
    methods text[] NOT NULL DEFAULT '{}',
    path_prefixes text[] NOT NULL DEFAULT '{}',
    max_ttl_seconds bigint,
    max_uses int,
    not_after timestamptz,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (secret_name IS NULL OR secret_tag IS NULL)
);

CREATE TABLE access_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_name text NOT NULL,
    secret_name text NOT NULL,
    mechanism text NOT NULL,
    constraints jsonb NOT NULL,
    -- Client-supplied context, encrypted at rest (request_id-bound AAD),
    -- purged with the request.
    context_ciphertext bytea,
    context_nonce bytea,
    context_wrapped_dek bytea,
    context_kek_id text,
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    deny_reason text,
    resolved_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    expires_at timestamptz NOT NULL,
    push_delivered_at timestamptz,
    push_attempts int NOT NULL DEFAULT 0,
    -- Rows created already-approved under a notify-only policy owe the
    -- operator an FYI push; the row is the outbox and the sweeper retries
    -- until push_delivered_at is set, same as approval pushes.
    notify_only boolean NOT NULL DEFAULT false,
    idem_client text NOT NULL,
    idem_key text NOT NULL,
    idem_mac bytea NOT NULL,
    UNIQUE (idem_client, idem_key)
);

CREATE INDEX access_requests_state_idx ON access_requests (state);
CREATE INDEX access_requests_fyi_outbox_idx ON access_requests (created_at)
    WHERE notify_only AND push_delivered_at IS NULL;

CREATE TABLE grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id uuid NOT NULL UNIQUE REFERENCES access_requests(id),
    client_name text NOT NULL,
    secret_name text NOT NULL,
    mechanism text NOT NULL,
    constraints jsonb NOT NULL,
    not_after timestamptz NOT NULL,
    max_uses int,
    use_count int NOT NULL DEFAULT 0,
    revoked boolean NOT NULL DEFAULT false,
    -- Approval-time secret entered but not stored; wrapped under the
    -- process-local ephemeral KEK when passthrough_ephemeral is true.
    passthrough_ciphertext bytea,
    passthrough_nonce bytea,
    passthrough_wrapped_dek bytea,
    passthrough_ephemeral boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX grants_not_after_idx ON grants (not_after);

-- Replay state: first use binds (grant, idempotency key) to the released
-- payload version.
CREATE TABLE grant_reads (
    grant_id uuid NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    idem_key text NOT NULL,
    secret_version_id uuid,
    passthrough boolean NOT NULL DEFAULT false,
    first_read_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (grant_id, idem_key)
);

-- Append-only. detail must never contain secret material or freeform client
-- context.
CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    kind text NOT NULL,
    request_id uuid,
    grant_id uuid,
    client_name text,
    secret_name text,
    secret_version_id uuid,
    actor text,
    method text,
    origin text,
    path text,
    status int,
    detail jsonb
);

CREATE INDEX audit_log_at_idx ON audit_log (at);
