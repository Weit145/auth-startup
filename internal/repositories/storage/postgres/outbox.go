package postgres

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

func (r *Repository) CreateEventOutbox(ctx context.Context, event event.Event) error {
	const query = `
	INSERT INTO event_outbox (event_id, type_event, user_id, email, verification_url, expires_at, created_at, status)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.db.Exec(ctx, query, event.EventID(), event.TypeEvent(), event.UserID(), event.Email(), event.VerificationURL(), event.ExpiresAt(), event.CreatedAt(), "pending")
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec create event outbox query: %w", err))
	}

	return nil
}

func (r *Repository) SetEventError(ctx context.Context, eventID uuid.UUID) error {
	const query = `
	UPDATE event_outbox
	SET status = 'error'
	WHERE event_id = $1`

	_, err := r.db.Exec(ctx, query, eventID)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec set event error query: %w", err))
	}

	return nil
}

func (r *Repository) SetDispatchingOutbox(ctx context.Context, event event.Event) error {
	const query = `
	UPDATE event_outbox
	SET status = 'dispatching'
	WHERE event_id = $1`

	_, err := r.db.Exec(ctx, query, event.EventID())
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec set pending outbox query: %w", err))
	}

	return nil
}
