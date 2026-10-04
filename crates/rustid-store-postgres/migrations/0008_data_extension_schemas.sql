-- Data extension schemas (the admin model's attribute schemas), keyed by
-- the lower-cased schema id, with the admin id and version the other
-- configuration tables have.
CREATE TABLE data_extension_schemas (
    name        text        PRIMARY KEY,
    id          uuid        NOT NULL UNIQUE,
    version     integer     NOT NULL DEFAULT 1,
    enabled     boolean     NOT NULL DEFAULT true,
    ordinal     integer     NOT NULL,
    data        jsonb       NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    updated     timestamptz NOT NULL DEFAULT now()
);
