package postgres

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	emailtokens "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/email_tokens"
	"github.com/Weit145/auth-startup/internal/repositories/storage/postgres/outbox"
	refreshsession "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/refresh_session"
	registrsession "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/registr_session"
	user_repo "github.com/Weit145/auth-startup/internal/repositories/storage/postgres/user"
	"github.com/google/uuid"
)

func (r *Repository) RegisterRequest(
	ctx context.Context,
	pendingUser domain.User,
	event event.Event,
	tokenHash domain.EmailVerificationTokenHash,
) error {
	tokenExpiresAt, ok := tokenHash.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin registration request tx: %w", err))
	}
	defer tx.Rollback(ctx)

	userIDDB, emailDB, roleDB, err := user_repo.IsertUser(ctx, tx, pendingUser)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert user: %w", err))
	}
	user, err := domain.NewUser(userIDDB, emailDB, roleDB)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("new user: %w", err))
	}

	err = emailtokens.IsertEmailVerificationToken(ctx, tx, user.ID(), tokenHash.Value(), tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert email verification token : %w", err))
	}

	err = outbox.InsertEventOutbox(ctx, tx, event)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert outbox: %w", err))
	}

	if err = tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit complete registration tx: %w", err))
	}

	return nil
}

func (r *Repository) ConfirmEmail(
	ctx context.Context,
	userID uuid.UUID,
	shortSessionToken domain.ShortSessionTokenHash,
	tokenEmailHash domain.EmailVerificationTokenHash,
) (domain.User, uuid.UUID, error) {
	if _, ok := shortSessionToken.ExpiresAt(); !ok {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("short session expiration is not set"))
	}
	if shortSessionToken.ID() == uuid.Nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("short session id is not set: %w", errs.ErrInvalidInput))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("begin verify email tx: %w", err))
	}
	defer tx.Rollback(ctx)

	verifiedUserID, err := emailtokens.VerifyEmail(ctx, tx, userID, tokenEmailHash.Value())
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("use email verification token: %w", err))
	}

	userIDDB, emailDB, roleDB, err := user_repo.GetPendingUserByID(ctx, tx, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}
	user, err := domain.NewUser(userIDDB, emailDB, roleDB)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("new user: %w", err))
	}

	err = registrsession.InvalidateSessions(ctx, tx, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}

	err = registrsession.InsertSession(ctx, tx, shortSessionToken, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, fmt.Errorf("commit complete registration tx: %w", err))
	}

	return *user, shortSessionToken.ID(), nil
}

func (r *Repository) RegisterComplete(
	ctx context.Context,
	sessionID uuid.UUID,
	passwordHash string,
	refreshToken domain.RefreshTokenHash,
) (domain.User, error) {
	refreshTokenExpiresAt, ok := refreshToken.ExpiresAt()
	if !ok {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("refresh token expiration is not set"))
	}
	if sessionID == uuid.Nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("registration session id is not set: %w", errs.ErrInvalidInput))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("begin complete registration tx: %w", err))
	}
	defer tx.Rollback(ctx)

	userID, err := registrsession.ConsumeSession(ctx, tx, sessionID)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("consume registration session: %w", err))
	}
	userIDDB, email, role, err := user_repo.CompleteUserRegistration(ctx, tx, userID, passwordHash)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("complete user registration: %w", err))
	}
	domainUser, err := domain.NewUser(userIDDB, email, role)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("new user: %w", err))
	}

	err = refreshsession.InsertRefreshSession(ctx, tx, userIDDB, refreshToken.Value(), refreshTokenExpiresAt)
	if err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("insert refresh session: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.User{}, logger.WrapError(ctx, fmt.Errorf("commit complete registration tx: %w", err))
	}

	return *domainUser, nil
}

func (r *Repository) RepeatEmail(
	ctx context.Context,
	email string,
	event event.Event,
	tokenEmailHash domain.EmailVerificationTokenHash,
) error {
	tokenExpiresAt, ok := tokenEmailHash.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("begin update email verification token tx: %w", err))
	}
	defer tx.Rollback(ctx)

	userID, emailDB, role, err := user_repo.GetUserByEmailForUpdate(ctx, tx, email)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("get user by email for update: %w", err))
	}
	domainUser, err := domain.NewUser(userID, emailDB, role)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("new user: %w", err))
	}

	if err := emailtokens.InvalidateEmailTokens(ctx, tx, domainUser.ID()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalidate email tokens: %w", err))
	}

	if err := emailtokens.IsertEmailVerificationToken(ctx, tx, domainUser.ID(), tokenEmailHash.Value(), tokenExpiresAt); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification token: %w", err))
	}

	if err := event.BindUserID(domainUser.ID()); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("bind user ID: %w", err))
	}

	err = outbox.InsertEventOutbox(ctx, tx, event)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert outbox: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("commit update email verification token tx: %w", err))
	}
	return nil
}
