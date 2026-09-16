package postgres

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/repositories/storage/postgres/outbox"
	passwordtokens "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/password_tokens"
	refreshsession "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/refresh_session"
	user_repo "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (r *Repository) PasswordRequest(
	ctx context.Context,
	email string,
	tokenHash domain.EmailVerificationTokenHash,
	event event.Event,
) error {
	tokenExpiresAt, ok := tokenHash.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("password reset token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin password request tx: %w", err))
	}
	defer tx.Rollback(ctx)

	id, emailDB, role, err := user_repo.GetVerifiedUserByEmailForUpdate(ctx, tx, email)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("get verified user by email tx: %w", err))
	}
	user, err := domain.NewUser(id, emailDB, role)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("build domain user: %w", err))
	}

	if err = passwordtokens.InvalidatePasswordResetTokens(ctx, tx, user.ID()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalid password reset tokens tx: %w", err))
	}

	if err = passwordtokens.InsertPasswordResetToken(ctx, tx, user.ID(), tokenHash.Value(), tokenExpiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("insert password reset token: %w", err))
	}
	if err := event.BindUserID(user.ID()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("bind user ID: %w", err))
	}

	err = outbox.InsertEventOutbox(ctx, tx, event)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert outbox: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit password request tx: %w", err))
	}
	return nil
}

func (r *Repository) PasswordConfirm(
	ctx context.Context,
	userID uuid.UUID,
	tokenHash domain.EmailVerificationTokenHash,
	passwordHash string,
) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin password confirm tx: %w", err))
	}
	defer tx.Rollback(ctx)

	verifiedUserID, err := passwordtokens.VerifyPasswordResetToken(ctx, tx, userID, tokenHash.Value())
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("use password reset token: %w", err))
	}

	id, email, role, err := user_repo.UpdateUserPassword(ctx, tx, verifiedUserID, passwordHash)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("update user password: %w", err))
	}
	user, err := domain.NewUser(id, email, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("create user: %w", err))
	}

	err = refreshsession.RevokeSessions(ctx, tx, user.ID())
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit password confirm tx: %w", err))
	}
	return *user, nil
}

func (r *Repository) ChangePassword(
	ctx context.Context,
	userID uuid.UUID,
	oldPassword, newPasswordHash string,
) (domain.User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin change password tx: %w", err))
	}
	defer tx.Rollback(ctx)

	id, email, role, passwordHash, err := user_repo.GetVerifiedUserWithActiveSession(ctx, tx, userID)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("get verified user with active session: %w", err))
	}

	user, err := domain.NewUser(id, email, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("build user from database row: %w", err))
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(oldPassword)); err != nil {
		return domain.User{}, logger.WrapError(ctx, errs.ErrUnauthorized)
	}

	_, _, _, err = user_repo.UpdateUserPassword(ctx, tx, user.ID(), newPasswordHash)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err = refreshsession.RevokeActiveUserSessions(ctx, tx, user.ID()); err != nil {
		return domain.User{}, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit change password tx: %w", err))
	}
	return *user, nil
}
