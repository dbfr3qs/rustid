-- Clients and resources keep the fixture-format JSON they were imported with
-- in `data`; typed columns hold what queries filter on. `ordinal` preserves
-- the configured order, which audiences and discovery lists follow.

CREATE TABLE clients (
    client_id   text        PRIMARY KEY,
    enabled     boolean     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);

-- Each allowed CORS origin reduced to its lower-case origin
-- (scheme://host[:port]), so the policy check is one indexed lookup.
CREATE TABLE client_cors_origins (
    client_id   text NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    origin      text NOT NULL,
    PRIMARY KEY (client_id, origin)
);
CREATE INDEX client_cors_origins_origin ON client_cors_origins (origin);

CREATE TABLE identity_resources (
    name        text        PRIMARY KEY,
    enabled     boolean     NOT NULL,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_scopes (
    name        text        PRIMARY KEY,
    enabled     boolean     NOT NULL,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_resources (
    name        text        PRIMARY KEY,
    enabled     boolean     NOT NULL,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);

-- Codes, refresh tokens, reference tokens, consents and the other grants
-- the persisted grant store holds. `key` is already hashed.
CREATE TABLE persisted_grants (
    key             text        PRIMARY KEY,
    type            text        NOT NULL,
    client_id       text        NOT NULL,
    subject_id      text,
    session_id      text,
    description     text,
    creation_time   timestamptz NOT NULL,
    expiration      timestamptz,
    consumed_time   timestamptz,
    data            text        NOT NULL
);
CREATE INDEX persisted_grants_subject ON persisted_grants (subject_id, client_id, type);
CREATE INDEX persisted_grants_session ON persisted_grants (subject_id, session_id, type);
CREATE INDEX persisted_grants_client ON persisted_grants (client_id, type);
CREATE INDEX persisted_grants_expiration ON persisted_grants (expiration);
