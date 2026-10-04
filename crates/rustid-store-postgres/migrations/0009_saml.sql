-- The SAML IdP's data: service providers (a configuration table, as
-- clients and resources are), sign-in state across the login round trip,
-- and logout sessions with the LogoutRequests they wait on.
CREATE TABLE saml_service_providers (
    entity_id   text        PRIMARY KEY,
    id          uuid        NOT NULL UNIQUE,
    version     integer     NOT NULL DEFAULT 1,
    enabled     boolean     NOT NULL,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE saml_signin_states (
    id          uuid        PRIMARY KEY,
    data        jsonb       NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX saml_signin_states_expires_at ON saml_signin_states (expires_at);

CREATE TABLE saml_logout_sessions (
    logout_id   text        PRIMARY KEY,
    data        jsonb       NOT NULL,
    expires_at  timestamptz NOT NULL
);
CREATE INDEX saml_logout_sessions_expires_at ON saml_logout_sessions (expires_at);

CREATE TABLE saml_logout_requests (
    request_id  text        PRIMARY KEY,
    logout_id   text        NOT NULL REFERENCES saml_logout_sessions (logout_id) ON DELETE CASCADE
);
CREATE INDEX saml_logout_requests_logout_id ON saml_logout_requests (logout_id);
