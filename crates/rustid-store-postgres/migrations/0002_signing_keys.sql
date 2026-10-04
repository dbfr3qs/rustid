-- Automatically managed signing keys. `data` holds the
-- key material, protected with the data protection key ring when
-- `data_protected` is set.
CREATE TABLE signing_keys (
    id                  text        PRIMARY KEY,
    version             integer     NOT NULL,
    created             timestamptz NOT NULL,
    algorithm           text        NOT NULL,
    is_x509_certificate boolean     NOT NULL,
    data                text        NOT NULL,
    data_protected      boolean     NOT NULL
);
