package user_repo

import (
	"context"
	"errors"
	"fmt"

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
) (id uuid.UUID, emailDB string, role string, passwordDB string, err error) {
	query := `
		SELECT id, email, role, password_hash
		FROM users
		WHERE email = $1 AND email_verified_at IS NULL
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, email).Scan(&id, &emailDB, &role, &passwordDB)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", "", logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", "", logger.WrapError(ctx, fmt.Errorf("query unverified user by email: %w", err))
	}
	return id, emailDB, role, passwordDB, nil
}
