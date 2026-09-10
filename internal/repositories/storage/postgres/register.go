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

	user, err := user_repo.IsertUser(ctx, tx, pendingUser)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert user: %w", err))
	}

	err = emailtokens.IsertEmailVerificationToken(ctx, tx, user.ID(), tokenHash.Value(), tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert email verification token : %w", err))
	}

	err = outbox.InsertEventOutbox(ctx, tx, event)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("isert outbox: %w", err))
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

	user, err := user_repo.GetPendingUserByID(ctx, tx, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}

	err = registrsession.InvalidateSessions(ctx, tx, verifiedUserID)
	if err != nil {
		return domain.User{}, uuid.Nil, logger.WrapError(ctx, err)
	}

	err = registrsession.InsertSession(ctx, tx, shortSessionToken, verifiedUserID)
	return *user, shortSessionToken.ID(), nil
}
