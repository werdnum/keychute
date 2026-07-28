-- Username for the `basic` (basic-password) injection kind (addendum #17):
-- Authorization: Basic base64(injection_username ":" secret).
ALTER TABLE secrets ADD COLUMN injection_username text;
