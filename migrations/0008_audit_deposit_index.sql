-- The deposit rate cap counts a client's `secret-created` rows in the last
-- hour, and it does so inside the deposit's own transaction while holding that
-- client's advisory lock (server/src/db/secrets.rs). With only
-- `audit_log_at_idx` that count scans every audit row in the window — proxy and
-- release events included, which on a busy deployment is most of them — so
-- deposits would get slower as unrelated traffic grew, holding the lock longer
-- each time.
--
-- Partial, because deposits are a tiny fraction of the log: the index only
-- covers the rows the predicate can match, and costs nothing on the write path
-- for every other audit kind.
CREATE INDEX audit_log_client_deposits_idx
    ON audit_log (client_name, at)
    WHERE kind = 'secret-created';
