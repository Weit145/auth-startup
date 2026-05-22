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

func (r *Repository) CreateUser(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error) {
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

	err = tx.QueryRow(ctx, createUserStmt, user.ID(), user.Email(), user.PasswordHash(), user.Name(), user.Role()).Scan(&id, &email, &name, &role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert user: %w", err))
	}

	createRefreshSessionStmt := `INSERT INTO refresh_sessions (user_id, refresh_token_hash, expires_at) VALUES ($1, $2, $3)`
	if _, err := tx.Exec(ctx, createRefreshSessionStmt, id, refreshTokenHash, refreshTokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	result, err := domain.UserFromID(ctx, id, email, name, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit create user tx: %w", err))
	}

	return *result, nil
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, name, role FROM users WHERE email = $1`

	var (
		id           uuid.UUID
		emailDB      string
		passwordHash string
		name         string
		role         string
	)

	err := r.db.QueryRow(ctx, query, email).Scan(&id, &emailDB, &passwordHash, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by email: %w", err))
	}

	result, err := domain.UserFromIDWithPasswordHash(ctx, id, emailDB, passwordHash, name, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func (r *Repository) AddSession(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin add session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	deleteExpiredSessionsStmt := `DELETE FROM refresh_sessions WHERE expires_at <= now()`
	if _, err := tx.Exec(ctx, deleteExpiredSessionsStmt); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("delete expired refresh sessions: %w", err))
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
