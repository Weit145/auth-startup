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

func (r *Repository) CreateUserWithEmailVerificationToken(ctx context.Context, user domain.User, tokenHash string, expiresAt time.Time) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin create user tx: %w", err))
	}
	defer tx.Rollback(ctx)

	createUserStmt := `
		INSERT INTO users (id, email, password_hash, name, role)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (email) DO UPDATE
		SET
			password_hash = EXCLUDED.password_hash,
			name = EXCLUDED.name
		WHERE users.email_verified_at IS NULL
		RETURNING id, email, name, role`

	var (
		id    uuid.UUID
		name  string
		email string
		role  string
	)

	err = tx.QueryRow(ctx, createUserStmt, user.ID(), user.Email(), user.PasswordHash(), user.Name(), user.Role()).Scan(&id, &email, &name, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, fmt.Errorf("upsert user: %w", errs.ErrAlreadyExists))
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("upsert user: %w", err))
	}

	invalidateVerificationTokensStmt := `
		UPDATE email_verification_tokens
		SET used_at = now()
		WHERE user_id = $1 AND used_at IS NULL
	`
	if _, err := tx.Exec(ctx, invalidateVerificationTokensStmt, id); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("invalidate email verification tokens: %w", err))
	}

	createVerificationTokenStmt := `
		INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	if _, err := tx.Exec(ctx, createVerificationTokenStmt, id, tokenHash, expiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert email verification token: %w", err))
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
	query := `
		SELECT id, email, password_hash, name, role, email_verified_at
		FROM users
		WHERE email = $1 AND email_verified_at IS NOT NULL
	`
	var (
		id              uuid.UUID
		emailDB         string
		passwordHash    string
		name            string
		role            string
		emailVerifiedAt time.Time
	)

	err := r.db.QueryRow(ctx, query, email).Scan(&id, &emailDB, &passwordHash, &name, &role, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by email: %w", err))
	}

	result, err := domain.UserVerification(ctx, id, emailDB, passwordHash, name, role, &emailVerifiedAt)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}

func (r *Repository) VerifyEmail(ctx context.Context, userID uuid.UUID, tokenHash string) (*domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("begin verify email tx: %w", err))
	}
	defer tx.Rollback(ctx)

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
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}

	verifyUserStmt := `
		UPDATE users
		SET email_verified_at = now()
		WHERE id = $1 AND email_verified_at IS NULL
		RETURNING id, email, password_hash, name, role, email_verified_at
	`

	var (
		id              uuid.UUID
		emailDB         string
		passwordHash    string
		name            string
		role            string
		emailVerifiedAt time.Time
	)

	err = tx.QueryRow(ctx, verifyUserStmt, verifiedUserID).Scan(&id, &emailDB, &passwordHash, &name, &role, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("verify user email: %w", err))
	}

	result, err := domain.UserVerification(ctx, id, emailDB, passwordHash, name, role, &emailVerifiedAt)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("commit verify email tx: %w", err))
	}

	return result, nil
}
