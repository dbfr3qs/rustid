-- Work to deliver reliably (OutboxProcessorHost): expired server-side
-- sessions to process. Each event carries its own retry state and lease,
-- so every instance can run the processor.
CREATE TABLE outbox (
    id            bigserial   PRIMARY KEY,
    event         text        NOT NULL,
    payload       text        NOT NULL,
    created       timestamptz NOT NULL,
    attempts      integer     NOT NULL DEFAULT 0,
    next_attempt  timestamptz NOT NULL,
    claimed_until timestamptz
);
CREATE INDEX outbox_due ON outbox (next_attempt, id);
