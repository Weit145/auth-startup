package user_repo

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

func GetPendingUserByID(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) (userIDDB uuid.UUID, emailDB string, roleDB string, err error) {
	query := `
			SELECT id, email, role
			FROM users
			WHERE id = $1
				AND email_verified_at IS NULL
		`

	err = tx.QueryRow(ctx, query, userID).Scan(&userIDDB, &emailDB, &roleDB)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("query user by id: %w", err))
	}

	return userIDDB, emailDB, roleDB, nil
}

func GetUserByEmailForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	email string,
) (id uuid.UUID, emailDB string, role string, err error) {
	query := `
		SELECT id, email, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NULL
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("query unverified user by email: %w", err))
	}
	return id, emailDB, role, nil
}

func GetAccountByEmailForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	email string,
) (id uuid.UUID, emailDB, role, passwordDB string, emailVerifiedAt time.Time, err error) {
	query := `
		SELECT id, email, role, password_hash, email_verified_at
		FROM users
		WHERE email = $1
			AND email_verified_at IS NOT NULL
			AND password_hash IS NOT NULL
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role, &passwordDB, &emailVerifiedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", "", time.Time{}, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", "", time.Time{}, logger.WrapError(ctx, fmt.Errorf("query verified account by email: %w", err))
	}
	return id, emailDB, role, passwordDB, emailVerifiedAt, nil
}

func GetVerifiedUserByEmailForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	email string,
) (id uuid.UUID, emailDB string, role string, err error) {
	query := `
		SELECT id, email, role
		FROM users
		WHERE email = $1 AND email_verified_at IS NOT NULL
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("query verified user by email: %w", err))
	}
	return id, emailDB, role, nil
}

func GetVerifiedUserWithActiveSession(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
) (id uuid.UUID, email string, role string, passwordHash string, err error) {
	query := `
		SELECT u.id, u.email, u.role, u.password_hash
		FROM users AS u
		WHERE u.id = $1
			AND u.email_verified_at IS NOT NULL
			AND EXISTS (
				SELECT 1
				FROM refresh_sessions AS rs
				WHERE rs.user_id = u.id
					AND rs.revoked_at IS NULL
					AND rs.expires_at > now()
			)
		FOR UPDATE
	`

	err = tx.QueryRow(ctx, query, userID).Scan(&id, &email, &role, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", "", logger.WrapError(ctx, errs.ErrUnauthorized)
		}
		return uuid.Nil, "", "", "", logger.WrapError(ctx, fmt.Errorf("query user with active session: %w", err))
	}

	return id, email, role, passwordHash, nil
}
