package registrsession

import (
	"context"
	"errors"
	"fmt"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func InvalidateSessions(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	const invalidateSessionsStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`
	if _, err := tx.Exec(ctx, invalidateSessionsStmt, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalidate registration sessions: %w", err))
	}
	return nil
}

func ConsumeSession(
	ctx context.Context,
	tx pgx.Tx,
	sessionID uuid.UUID,
) (userID uuid.UUID, err error) {
	const consumeSessionStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE id = $1
			AND used_at IS NULL
			AND expires_at > now()
		RETURNING user_id
	`
	if err := tx.QueryRow(ctx, consumeSessionStmt, sessionID).Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return uuid.Nil, logger.WrapError(ctx, fmt.Errorf("consume registration session: %w", err))
	}
	return userID, nil
}

func InvalidateSession(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	const invalidateRegistrationSessionsStmt = `
		UPDATE registration_sessions
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`
	if _, err := tx.Exec(ctx, invalidateRegistrationSessionsStmt, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalidate registration sessions: %w", err))
	}
	return nil
}
