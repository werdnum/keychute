-- AWS SigV4 request signing as an injection kind. The template's access key
-- id lives in injection_username and its `region/service` scope in
-- injection_header; the stored secret is the secret access key.
ALTER TABLE secrets DROP CONSTRAINT secrets_injection_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_injection_kind_check
    CHECK (injection_kind IN ('bearer', 'header', 'basic', 'basic-password', 'aws-sigv4'));

-- Rows reconciled from the declarative config (`secrets:` / `policies:`) at
-- startup. The config is their source of truth: reconciliation creates,
-- updates and removes them, and the UI refuses to edit them, since an edit
-- there would be silently reverted by the next restart.
ALTER TABLE secrets ADD COLUMN managed_by_config boolean NOT NULL DEFAULT false;
ALTER TABLE policies ADD COLUMN managed_by_config boolean NOT NULL DEFAULT false;
