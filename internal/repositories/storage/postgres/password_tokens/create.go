package passwordtokens

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func InsertPasswordResetToken(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	tokenHash string,
	expiresAt time.Time,
) error {
	createPasswordResetTokenStmt := `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	if _, err := tx.Exec(ctx, createPasswordResetTokenStmt, userID, tokenHash, expiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert password reset token: %w", err))
	}

	return nil
}
