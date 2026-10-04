-- One-time values (the replay cache: client assertion and DPoP proof jti)
-- until they expire, so every instance sees the others' uses.
CREATE TABLE replay_cache (
    key     text        PRIMARY KEY,
    expires timestamptz NOT NULL
);
CREATE INDEX replay_cache_expires ON replay_cache (expires);

-- Polling throttling (device and CIBA): the last poll per key.
CREATE TABLE throttling (
    key       text        PRIMARY KEY,
    last_seen timestamptz NOT NULL,
    forget    timestamptz NOT NULL
);
CREATE INDEX throttling_forget ON throttling (forget);

-- The storage purge removes consumed grants by consumption time.
CREATE INDEX persisted_grants_consumed ON persisted_grants (consumed_time)
    WHERE consumed_time IS NOT NULL;
