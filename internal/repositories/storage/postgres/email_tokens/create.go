package emailtokens

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/jackc/pgx/v5"
)

func IsertEmailVerificationToken(ctx context.Context, tx pgx.Tx, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	createVerificationTokenStmt := `
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	if _, err := tx.Exec(ctx, createVerificationTokenStmt, userID, tokenHash, expiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert email verification token: %w", err))
	}

	return nil
}
