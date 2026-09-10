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

func GetPendingUserByID(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (*domain.User, error) {
	query := `
			SELECT id, email, role
			FROM users
			WHERE id = $1
				AND email_verified_at IS NULL
		`
	var (
		id      uuid.UUID
		emailDB string
		role    string
	)

	err := tx.QueryRow(ctx, query, userID).Scan(&id, &emailDB, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, logger.WrapError(ctx, errs.ErrNotFound)
		}
		return nil, logger.WrapError(ctx, fmt.Errorf("query user by id: %w", err))
	}

	result, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	return result, nil
}
