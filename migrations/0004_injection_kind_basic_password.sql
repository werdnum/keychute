-- Widen the injection_kind CHECK to accept 'basic-password' as an alias of
-- 'basic'. Code normalizes UI input to 'basic' and accepts both spellings on
-- read (server/src/proxy.rs); the widened constraint keeps rows written by
-- external tooling using the documented 'basic-password' name valid.
ALTER TABLE secrets DROP CONSTRAINT secrets_injection_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_injection_kind_check
    CHECK (injection_kind IN ('bearer', 'header', 'basic', 'basic-password'));
