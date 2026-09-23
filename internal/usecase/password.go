package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

func (s *Service) PasswordRequest(
	ctx context.Context,
	email string,
) error {
	token, err := s.tokens.CreateEmailVerificationToken()
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err))
	}
	token.CreateExpiresAt(s.cfg.EmailVerificationTokenTTL)
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tokenHash, err := s.tokens.HashEmailVerificationToken(token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash token for email verification: %w", err))
	}

	event, err := event.NewEvent(email, s.cfg.EmailVerificationURL, token, tokenExpiresAt, nil, event.ResetPasswordType)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
	}

	err = s.repo.PasswordRequest(ctx, email, tokenHash, event)
	if errors.Is(err, errs.ErrNotFound) {
		return nil
	}
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create event outbox: %w", err))
	}
	return nil
}

func (s *Service) PasswordConfirm(
	ctx context.Context,
	userID uuid.UUID,
	token, newPassword string,
) error {
	if userID == uuid.Nil {
		return logger.WrapError(ctx, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput))
	}
	tokenEmailDomain, err := domain.NewEmailVerificationToken(token, nil)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	tokenEmailHash, err := s.tokens.HashEmailVerificationToken(tokenEmailDomain)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash email verification token: %w", err))
	}
	passwordHash, err := domain.HashPassword(newPassword)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash password: %w", err))
	}
	result, err := s.repo.PasswordConfirm(ctx, userID, tokenEmailHash, passwordHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("confirm password reset: %w", err))
	}
	ctx = logger.WithLogID(ctx, result.ID())

	return nil
}

func (s *Service) ChangePassword(
	ctx context.Context,
	userID uuid.UUID,
	oldPassword, newPassword string,
) error {
	if userID == uuid.Nil {
		return logger.WrapError(ctx, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput))
	}
	newPassword, err := valid.NormalizePassword(newPassword)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalid new password: %w", err))
	}
	oldPassword, err = valid.NormalizePassword(oldPassword)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("invalid old password: %w", err))
	}

	newPasswordHash, err := domain.HashPassword(newPassword)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash password: %w", err))
	}
	result, err := s.repo.ChangePassword(ctx, userID, oldPassword, newPasswordHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("change password: %w", err))
	}
	ctx = logger.WithLogID(ctx, result.ID())

	return nil
}
