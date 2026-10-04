-- Device authorizations, keyed by the hashes of the
-- device code and the user code.
CREATE TABLE device_codes (
    device_code   text        PRIMARY KEY,
    user_code     text        NOT NULL UNIQUE,
    client_id     text        NOT NULL,
    subject_id    text,
    creation_time timestamptz NOT NULL,
    expiration    timestamptz NOT NULL,
    data          text        NOT NULL
);
CREATE INDEX device_codes_expiration ON device_codes (expiration);
