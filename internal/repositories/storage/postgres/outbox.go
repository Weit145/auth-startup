package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

func (r *Repository) CreateEventOutbox(
	ctx context.Context,
	event event.Event,
) error {
	const query = `
	INSERT INTO event_outbox (event_id, type_event, user_id, email, verification_url, expires_at, created_at, status)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.db.Exec(ctx, query, event.EventID(), event.TypeEvent().String(), event.UserID(), event.Email(), event.VerificationURL(), event.ExpiresAt(), event.CreatedAt(), "pending")
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec create event outbox query: %w", err))
	}

	return nil
}

func (r *Repository) SetEventError(
	ctx context.Context,
	eventID uuid.UUID,
) error {
	const query = `
	UPDATE event_outbox
	SET status = 'error',
		locked_at = NULL
	WHERE event_id = $1`

	_, err := r.db.Exec(ctx, query, eventID)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec set event error query: %w", err))
	}

	return nil
}

func (r *Repository) ReleaseEventForRetry(
	ctx context.Context,
	eventID uuid.UUID,
	lastError string,
) error {
	const query = `
	UPDATE event_outbox
	SET status = 'pending',
		locked_at = NULL,
		attempts = attempts + 1,
		next_attempt_at = now() + make_interval(
			secs => LEAST(60, power(2, LEAST(attempts, 6))::integer)
		),
		last_error = $2
	WHERE event_id = $1
		AND status = 'dispatching'`

	commandTag, err := r.db.Exec(ctx, query, eventID, lastError)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec release outbox event for retry query: %w", err))
	}
	if commandTag.RowsAffected() != 1 {
		return logger.WrapError(ctx, fmt.Errorf("release outbox event for retry: event %s is not dispatching", eventID))
	}

	return nil
}

func (r *Repository) ClaimPendingOutbox(
	ctx context.Context,
	limit int,
) ([]event.Event, error) {
	const query = `
	WITH selected AS (
		SELECT id
		FROM event_outbox
		WHERE (
			status = 'pending'
			AND next_attempt_at <= now()
		)
		OR (
			status = 'dispatching'
			AND (
				locked_at IS NULL
				OR locked_at < now() - interval '15 minutes'
			)
		)
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	)
	UPDATE event_outbox AS o
	SET status = 'dispatching',
		locked_at = now()
	FROM selected
	WHERE o.id = selected.id
	RETURNING
		o.event_id,
		o.type_event,
		o.user_id,
		o.email,
		o.verification_url,
		o.expires_at,
		o.created_at
`

	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("exec read event outbox query: %w", err))
	}
	defer rows.Close()

	var events []event.Event
	for rows.Next() {
		var (
			eventID         uuid.UUID
			typeEvent       string
			userID          uuid.UUID
			email           string
			verificationURL string
			expiresAt       time.Time
			createdAt       time.Time
		)
		if err := rows.Scan(
			&eventID,
			&typeEvent,
			&userID,
			&email,
			&verificationURL,
			&expiresAt,
			&createdAt,
		); err != nil {
			return nil, logger.WrapError(ctx, fmt.Errorf("scan event outbox row: %w", err))
		}
		restoredEvent, err := event.RestoreEvent(eventID, typeEvent, &userID, email, verificationURL, expiresAt, createdAt)
		if err != nil {
			return nil, logger.WrapError(ctx, fmt.Errorf("restore event: %w", err))
		}
		events = append(events, restoredEvent)
	}
	if err := rows.Err(); err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("iterate event outbox rows: %w", err))
	}

	return events, nil
}

func (r *Repository) SetEventPublished(
	ctx context.Context, eventID uuid.UUID,
) error {
	const query = `
	UPDATE event_outbox
	SET status = 'published',
		locked_at = NULL,
		last_error = NULL
	WHERE event_id = $1
		AND status = 'dispatching'`

	commandTag, err := r.db.Exec(ctx, query, eventID)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec set published outbox query: %w", err))
	}
	if commandTag.RowsAffected() != 1 {
		return logger.WrapError(ctx, fmt.Errorf("set outbox event published: event %s is not dispatching", eventID))
	}

	return nil
}
