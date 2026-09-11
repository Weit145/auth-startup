package refreshsession

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/jackc/pgx/v5"
)

func InsertRefreshSession(ctx context.Context, tx pgx.Tx, userID uuid.UUID, refreshTokenHash string, refreshTokenExpiresAt time.Time) error {

	createRefreshSessionStmt := `
		INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, userID, refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	return nil
}
