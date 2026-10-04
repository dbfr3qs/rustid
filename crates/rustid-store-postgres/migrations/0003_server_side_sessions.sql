-- Server-side sessions. Keys sort ordinally
-- (COLLATE "C"), as the paging of session queries expects.
CREATE TABLE server_side_sessions (
    key          text COLLATE "C" PRIMARY KEY,
    scheme       text        NOT NULL,
    subject_id   text        NOT NULL,
    session_id   text        NOT NULL,
    display_name text,
    created      timestamptz NOT NULL,
    renewed      timestamptz NOT NULL,
    expires      timestamptz,
    data         text        NOT NULL
);
CREATE INDEX server_side_sessions_subject ON server_side_sessions (subject_id);
CREATE INDEX server_side_sessions_session ON server_side_sessions (session_id);
CREATE INDEX server_side_sessions_expires ON server_side_sessions (expires);
