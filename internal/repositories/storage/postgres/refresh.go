package postgres

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	refreshsession "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/refresh_session"
)

func (r *Repository) RotateSession(
	ctx context.Context,
	oldToken, newToken domain.RefreshTokenHash,
) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin rotate session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	id, email, role, err := refreshsession.RotateSession(ctx, tx, oldToken, newToken)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("rotate session tx: %w", err))
	}
	user, err := domain.NewUser(id, email, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit rotate session tx: %w", err))
	}

	return *user, nil
}
