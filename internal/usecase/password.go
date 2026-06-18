package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type PasswordService interface {
	PasswordRequest(ctx context.Context, email string) error
	PasswordConfirm(ctx context.Context, userID uuid.UUID, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
}

func (s *Service) PasswordRequest(ctx context.Context, email string) error {
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

	result, err := s.repo.PasswordRequest(ctx, email, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create password reset token: %w", err))
	}
	ctx = logger.WithLogID(ctx, result.ID())

	emailEvent, err := domain.NewEmail(result.ID(), result.Email(), token, tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
	}

	err = s.notifications.PublishEvent(ctx, emailEvent, s.cfg.EmailVerificationURL)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("publish email: %w", err))
	}

	return nil
}

func (s *Service) PasswordConfirm(ctx context.Context, userID uuid.UUID, token, newPassword string) error {
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

func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
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
