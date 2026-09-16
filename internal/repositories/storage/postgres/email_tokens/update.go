package emailtokens

import (
	"context"
	"errors"
	"fmt"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func VerifyEmail(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	tokenHash string,
) (userIDDB uuid.UUID, err error) {
	useTokenStmt := `
		UPDATE email_verification_tokens
		SET used_at = now()
		WHERE user_id = $1
			AND token_hash = $2
			AND used_at IS NULL
			AND expires_at > now()
		RETURNING user_id
	`

	if err := tx.QueryRow(ctx, useTokenStmt, userID, tokenHash).Scan(&userIDDB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return uuid.Nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}
	return userIDDB, nil
}

func InvalidateEmailTokens(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	invalidateVerificationTokensStmt := `
		UPDATE email_verification_tokens
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`

	if _, err := tx.Exec(ctx, invalidateVerificationTokensStmt, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalidate email verification tokens: %w", err))
	}

	return nil
}
