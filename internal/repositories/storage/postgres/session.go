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

func (r *Repository) AddSession(ctx context.Context, user domain.User, token domain.Token) (domain.User, error) {
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("refresh token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin add session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	if err := AddSessionTx(ctx, tx, user.ID(), token.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit add session tx: %w", err))
	}

	return user, nil
}

func AddSessionTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, refreshTokenHash string, refreshTokenExpiresAt time.Time) error {

	createRefreshSessionStmt := `
		INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, userID, refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	return nil
}

func (r *Repository) RevokeSession(ctx context.Context, userID uuid.UUID, token domain.Token) error {
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
	if _, err := tx.Exec(ctx, revokeSessionStmt, userID, token.Value()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("revoke refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit revoke session tx: %w", err))
	}

	return nil
}

func (r *Repository) RotateSession(ctx context.Context, oldToken, newToken domain.Token) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin rotate session tx: %w", err))
	}
	defer tx.Rollback(ctx)

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
				u.name,
				u.role
		`

	var (
		id    uuid.UUID
		email string
		name  string
		role  string
	)

	err = tx.QueryRow(ctx, rotateSessionStmt, oldToken.Value(), newToken.Value()).
		Scan(&id, &email, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("rotate refresh session: %w", err))
	}

	user, err := domain.NewUser(ctx, id, email, name, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit rotate session tx: %w", err))
	}

	return *user, nil
}
