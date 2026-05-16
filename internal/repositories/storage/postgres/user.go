package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

func (r *Repository) CreateUser(ctx context.Context, user domain.User, passwordHash, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin create user tx: %w", err))
	}
	defer tx.Rollback(ctx)

	createUserStmt := `INSERT INTO users (id, email, password_hash, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, name, role`

	var (
		id    uuid.UUID
		name  string
		email string
		role  string
	)

	err = tx.QueryRow(ctx, createUserStmt, user.ID(), user.Email(), passwordHash, user.Name(), user.Role()).Scan(&id, &email, &name, &role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert user: %w", err))
	}

	createRefreshSessionStmt := `INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at) VALUES ($1, $2, $3)`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, id, refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	result, err := domain.UserFromID(id, email, name, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit create user tx: %w", err))
	}

	return *result, nil
}
