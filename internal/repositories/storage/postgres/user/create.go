package user_repo

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

func IsertUser(
	ctx context.Context,
	tx pgx.Tx,
	user domain.User,
) (userIDDB uuid.UUID, emailDB string, roleDB string, err error) {
	const insertUserStmt = `
		INSERT INTO users (id, email, password_hash, role)
		VALUES ($1, $2, NULL, $3)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, role
	`

	err = tx.QueryRow(ctx, insertUserStmt, user.ID(), user.Email(), user.Role()).
		Scan(&userIDDB, &emailDB, &roleDB)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.UUID{}, "", "", logger.WrapError(ctx, fmt.Errorf("create pending user: %w", errs.ErrAlreadyExists))
		}
		return uuid.UUID{}, "", "", logger.WrapError(ctx, fmt.Errorf("create pending user: %w", err))
	}
	return userIDDB, emailDB, roleDB, nil
}
