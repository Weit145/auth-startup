package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func InvalidateEmailVerificationTokens(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
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

func AddEmailVerificationToken(ctx context.Context, tx pgx.Tx, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	createVerificationTokenStmt := `
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	if _, err := tx.Exec(ctx, createVerificationTokenStmt, userID, tokenHash, expiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert email verification token: %w", err))
	}

	return nil
}

func VerifyEmail(ctx context.Context, tx pgx.Tx, userID uuid.UUID, tokenHash string) (uuid.UUID, error) {
	useTokenStmt := `
		UPDATE email_verification_tokens
		SET used_at = now()
		WHERE user_id = $1
			AND token_hash = $2
			AND used_at IS NULL
			AND expires_at > now()
		RETURNING user_id
	`

	var verifiedUserID uuid.UUID
	if err := tx.QueryRow(ctx, useTokenStmt, userID, tokenHash).Scan(&verifiedUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}
	return verifiedUserID, nil
}
