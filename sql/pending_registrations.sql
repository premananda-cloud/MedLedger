CREATE TABLE pending_registrations (
    id                  SERIAL PRIMARY KEY,
    email               TEXT NOT NULL,
    username            TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    signing_public_key  VARCHAR(64) NOT NULL,
    exchange_public_key VARCHAR(64) NOT NULL,
    verification_code   VARCHAR(64) NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '24 hours'),
    attempts            INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX ON pending_registrations(lower(email));
CREATE UNIQUE INDEX ON pending_registrations(lower(username));
CREATE INDEX ON pending_registrations(expires_at);
