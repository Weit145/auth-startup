package refreshsession

import (
	"context"
	"errors"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func RevokeSession(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	token string,
) error {
	revokeSessionStmt := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND refresh_token_hash = $2
			AND revoked_at IS NULL
	`
	if _, err := tx.Exec(ctx, revokeSessionStmt, userID, token); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke refresh session: %w", err))
	}
	return nil
}

func RevokeSessions(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	revokeSessionStmt := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND revoked_at IS NULL
	`
	if _, err := tx.Exec(ctx, revokeSessionStmt, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke refresh session: %w", err))
	}

	return nil
}

func RevokeActiveUserSessions(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) error {
	query := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND revoked_at IS NULL
			AND expires_at > now()
	`

	if _, err := tx.Exec(ctx, query, userID); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke active user sessions: %w", err))
	}

	return nil
}

func RotateSession(
	ctx context.Context,
	tx pgx.Tx,
	oldToken, newToken domain.RefreshTokenHash,
) (id uuid.UUID, email, role string, err error) {
	rotateSessionStmt := `
			UPDATE refresh_sessions AS rs
			SET
				refresh_token_hash = $2
			FROM users AS u
			WHERE rs.refresh_token_hash = $1
				AND u.id = rs.user_id
				AND rs.revoked_at IS NULL
				AND rs.expires_at > now()
				AND u.email_verified_at IS NOT NULL
			RETURNING
				u.id,
				u.email,
				u.role
		`
	err = tx.QueryRow(ctx, rotateSessionStmt, oldToken.Value(), newToken.Value()).
		Scan(&id, &email, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("rotate refresh session: %w", err))
	}
	return id, email, role, nil
}
