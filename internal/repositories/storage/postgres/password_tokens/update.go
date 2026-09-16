package passwordtokens

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/jackc/pgx/v5"
)

func InvalidatePasswordResetTokens(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	invalidatePasswordResetTokensStmt := `
		UPDATE password_reset_tokens
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`

	if _, err := tx.Exec(ctx, invalidatePasswordResetTokensStmt, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalidate password reset tokens: %w", err))
	}

	return nil
}

func VerifyPasswordResetToken(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	tokenHash string,
) (verifiedUserID uuid.UUID, err error) {
	useTokenStmt := `
		UPDATE password_reset_tokens
		SET used_at = now()
		WHERE user_id = $1
			AND token_hash = $2
			AND used_at IS NULL
			AND expires_at > now()
		RETURNING user_id
	`

	if err = tx.QueryRow(ctx, useTokenStmt, userID, tokenHash).Scan(&verifiedUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return uuid.Nil, logger.WrapError(ctx, fmt.Errorf("use password reset token: %w", err))
	}
	return verifiedUserID, nil
}
