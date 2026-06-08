package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *Repository) AddSession(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin add session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	if err := AddSessionTx(ctx, tx, user.ID(), refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit add session tx: %w", err))
	}

	return user, nil
}

func AddSessionTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, refreshTokenHash string, refreshTokenExpiresAt time.Time) error {
	if err := DeleteExpiredSessions(ctx, tx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete expired sessions: %w", err))
	}

	createRefreshSessionStmt := `
		INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, userID, refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	return nil
}

func (r *Repository) RevokeSession(ctx context.Context, userID uuid.UUID, refreshTokenHash string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin revoke session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	revokeSessionStmt := `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE user_id = $1
			AND refresh_token_hash = $2
			AND revoked_at IS NULL
	`
	if _, err := tx.Exec(ctx, revokeSessionStmt, userID, refreshTokenHash); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit revoke session tx: %w", err))
	}

	return nil
}

func (r *Repository) ValidateSession(ctx context.Context, refreshTokenHash string) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin validate session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	if err := DeleteExpiredSessions(ctx, tx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("delete expired sessions: %w", err))
	}

	validateSessionStmt := `
		SELECT
			u.id,
			u.email,
			u.password_hash,
			u.name,
			u.role,
			u.email_verified_at
		FROM refresh_sessions AS rs
		JOIN users AS u ON u.id = rs.user_id
		WHERE rs.refresh_token_hash = $1
			AND rs.revoked_at IS NULL
			AND rs.expires_at > now()
			AND u.email_verified_at IS NOT NULL
		FOR SHARE OF rs, u
	`

	var (
		id              uuid.UUID
		email           string
		passwordHash    string
		name            string
		role            string
		emailVerifiedAt time.Time
	)

	err = tx.QueryRow(ctx, validateSessionStmt, refreshTokenHash).
		Scan(&id, &email, &passwordHash, &name, &role, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("validate refresh session: %w", err))
	}

	user, err := domain.UserVerification(ctx, id, email, passwordHash, name, role, &emailVerifiedAt)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit validate session tx: %w", err))
	}

	return *user, nil
}

func DeleteExpiredSessions(ctx context.Context, db pgx.Tx) error {
	deleteExpiredSessionsStmt := `DELETE FROM refresh_sessions WHERE expires_at <= now()`
	if _, err := db.Exec(ctx, deleteExpiredSessionsStmt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete expired refresh sessions: %w", err))
	}
	return nil
}
