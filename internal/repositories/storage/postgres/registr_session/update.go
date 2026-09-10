package registrsession

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func InvalidateSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
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
