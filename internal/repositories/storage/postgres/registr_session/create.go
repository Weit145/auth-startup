package registrsession

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func InsertSession(ctx context.Context, tx pgx.Tx, shortSessionToken domain.ShortSessionTokenHash, userID uuid.UUID) error {
	const addSessionStmt = `
		INSERT INTO registration_sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`
	shortSessionExpiresAt, ok := shortSessionToken.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("short session expiration is not set"))
	}
	if _, err := tx.Exec(
		ctx,
		addSessionStmt,
		shortSessionToken.ID(),
		userID,
		shortSessionToken.Value(),
		shortSessionExpiresAt,
	); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert registration session: %w", err))
	}
	return nil
}
