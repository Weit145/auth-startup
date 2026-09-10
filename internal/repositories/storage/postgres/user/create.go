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

func IsertUser(ctx context.Context, tx pgx.Tx, user domain.User) (domain.User, error) {
	const insertUserStmt = `
		INSERT INTO users (id, email, password_hash, role)
		VALUES ($1, $2, NULL, $3)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, role
	`
	var (
		id            uuid.UUID
		emailDB, role string
	)

	err := tx.QueryRow(ctx, insertUserStmt, user.ID(), user.Email(), user.Role()).
		Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create pending user: %w", errs.ErrAlreadyExists))
		}
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create pending user: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build pending user: %w", err))
	}
	return *result, nil
}
