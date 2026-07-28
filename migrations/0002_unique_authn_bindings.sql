-- Addendum #2: a credential must resolve to at most one client row.
CREATE UNIQUE INDEX clients_api_token_sha256_unique
    ON clients (api_token_sha256)
    WHERE api_token_sha256 IS NOT NULL;

CREATE UNIQUE INDEX clients_sa_binding_unique
    ON clients (sa_audience, sa_subject)
    WHERE sa_audience IS NOT NULL AND sa_subject IS NOT NULL;
