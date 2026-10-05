-- Upstream identity providers (a configuration table, as clients and SAML
-- service providers are), keyed by scheme. Inline secrets and private keys
-- in data are encrypted with data protection.
CREATE TABLE identity_providers (
    scheme      text        PRIMARY KEY,
    id          uuid        NOT NULL UNIQUE,
    version     integer     NOT NULL DEFAULT 1,
    enabled     boolean     NOT NULL,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);
