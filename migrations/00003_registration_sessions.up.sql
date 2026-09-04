-- +goose Up

ALTER TABLE users
    DROP COLUMN IF EXISTS name,
    ALTER COLUMN password_hash DROP NOT NULL;

CREATE TABLE registration_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_registration_sessions_user_id
ON registration_sessions(user_id);

CREATE INDEX idx_registration_sessions_expires_at
ON registration_sessions(expires_at);

CREATE UNIQUE INDEX idx_registration_sessions_active_user_id
ON registration_sessions(user_id)
WHERE used_at IS NULL;
