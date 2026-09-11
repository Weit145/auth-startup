package outbox

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/jackc/pgx/v5"
)

func InsertEventOutbox(
	ctx context.Context,
	tx pgx.Tx,
	event event.Event,
) error {
	const query = `
	INSERT INTO event_outbox (event_id, type_event, user_id, email, verification_url, expires_at, created_at, status)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := tx.Exec(ctx, query, event.EventID(), event.TypeEvent(), event.UserID(), event.Email(), event.VerificationURL(), event.ExpiresAt(), event.CreatedAt(), "pending")
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("exec create event outbox query: %w", err))
	}

	return nil
}
