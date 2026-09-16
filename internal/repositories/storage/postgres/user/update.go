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

func CompleteUserRegistration(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	passwordHash string,
) (userIDDB uuid.UUID, emailDB string, roleDB string, err error) {
	const completeUserStmt = `
		UPDATE users
		SET password_hash = $2,
			email_verified_at = now()
		WHERE id = $1
			AND email_verified_at IS NULL
		RETURNING id, email, role
	`
	if err := tx.QueryRow(ctx, completeUserStmt, userID, passwordHash).Scan(&userIDDB, &emailDB, &roleDB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrAlreadyExists)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("complete user account: %w", err))
	}
	return userIDDB, emailDB, roleDB, nil
}

func UpdateUserPassword(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	passwordHash string,
) (id uuid.UUID, email string, role string, err error) {
	query := `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1 AND email_verified_at IS NOT NULL
		RETURNING id, email, role
	`

	err = tx.QueryRow(ctx, query, userID, passwordHash).Scan(&id, &email, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, "", "", logger.WrapError(ctx, errs.ErrNotFound)
		}
		return uuid.Nil, "", "", logger.WrapError(ctx, fmt.Errorf("update user password: %w", err))
	}

	return id, email, role, nil
}
