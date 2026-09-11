package postgres

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	refreshsession "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/refresh_session"
	user_repo "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/user"
	"github.com/google/uuid"
)

func (r *Repository) GetAccountByEmail(
	ctx context.Context,
	email string,
) (domain.Account, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.Account{}, logger.WrapError(ctx, fmt.Errorf("begin update email verification token tx: %w", err))
	}
	defer tx.Rollback(ctx)

	userID, emailDB, role, passwordDB, err := user_repo.GetAccountByEmailForUpdate(ctx, tx, email)
	if err != nil {
		return domain.Account{}, logger.WrapError(ctx, fmt.Errorf("get user by email for update: %w", err))
	}

	account, err := domain.CreateUserAccount(userID, emailDB, passwordDB, role, nil)
	if err != nil {
		return domain.Account{}, logger.WrapError(ctx, fmt.Errorf("new account: %w", err))
	}
	return *account, nil
}

func (r *Repository) AddSession(
	ctx context.Context,
	user domain.User,
	token domain.RefreshTokenHash,
) (domain.User, error) {
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("refresh token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin add session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	if err := refreshsession.InsertRefreshSession(ctx, tx, user.ID(), token.Value(), tokenExpiresAt); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit add session tx: %w", err))
	}

	return user, nil
}

func (r *Repository) RevokeSession(
	ctx context.Context,
	userID uuid.UUID,
	token domain.RefreshTokenHash,
) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin revoke session tx: %w", err))
	}
	defer tx.Rollback(ctx)

	if err := refreshsession.RevokeSession(ctx, tx, userID, token.Value()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("delete refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit revoke session tx: %w", err))
	}

	return nil
}
