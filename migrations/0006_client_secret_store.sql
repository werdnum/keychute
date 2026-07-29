-- Client-initiated secret deposit (`POST /v1/secrets`). Off by default: a
-- client may only store a secret when the operator says so in config, so
-- adding the endpoint cannot widen any existing deployment's blast radius.
ALTER TABLE clients ADD COLUMN may_store_secrets boolean NOT NULL DEFAULT false;
