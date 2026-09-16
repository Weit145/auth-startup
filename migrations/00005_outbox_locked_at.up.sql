-- +goose Up
ALTER TABLE event_outbox
    ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_error TEXT;

ALTER TABLE event_outbox
    DROP CONSTRAINT IF EXISTS event_outbox_status_check;

ALTER TABLE event_outbox
    ADD CONSTRAINT event_outbox_status_check
    CHECK (status IN ('pending', 'dispatching', 'published', 'error'));

DROP INDEX IF EXISTS idx_event_outbox_claim;

CREATE INDEX idx_event_outbox_claim
    ON event_outbox (status, next_attempt_at, locked_at, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_event_outbox_event_id
    ON event_outbox (event_id);
