package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
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

	err = DeleteExpiredSessions(ctx, tx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("delete expired sessions: %w", err))
	}

	createRefreshSessionStmt := `INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at) VALUES ($1, $2, $3)`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, user.ID(), refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit add session tx: %w", err))
	}

	return user, nil
}

func (r *Repository) DeleteSession(ctx context.Context, userID uuid.UUID, refreshTokenHash string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin delete session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	err = DeleteExpiredSessions(ctx, tx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete expired sessions: %w", err))
	}

	deleteSessionStmt := `DELETE FROM refresh_sessions WHERE user_id = $1 AND refresh_token_hash = $2`
	if _, err := tx.Exec(ctx, deleteSessionStmt, userID, refreshTokenHash); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit delete session tx: %w", err))
	}

	return nil
}

func DeleteExpiredSessions(ctx context.Context, db pgx.Tx) error {
	deleteExpiredSessionsStmt := `DELETE FROM refresh_sessions WHERE expires_at <= now()`
	if _, err := db.Exec(ctx, deleteExpiredSessionsStmt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete expired refresh sessions: %w", err))
	}
	return nil
}
