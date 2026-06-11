package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type RegisterService interface {
	Register(ctx context.Context, email, password, name string) error
	ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.User, domain.Tokens, error)
}

func (s *Service) Register(ctx context.Context, email, password, name string) error {
	account, err := domain.NewUserAccount(email, password, name)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create domain account: %w", err))
	}

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

	result, err := s.repo.CreateUserWithEmailVerificationToken(ctx, *account, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create user with email verification token: %w", err))
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

func (s *Service) ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.User, domain.Tokens, error) {
	tokenEmailDomain, err := domain.NewEmailVerificationToken(token, nil)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	tokenEmailHash, err := s.tokens.HashEmailVerificationToken(tokenEmailDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash email verification token: %w", err))
	}
	refreshToken, err := s.tokens.CreateRefreshToken()
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshToken.CreateExpiresAt(s.cfg.RefreshTokenTTL)
	refreshTokenHash, err := s.tokens.HashRefreshToken(refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}
	user, err := s.repo.VerifyEmailAndAddSession(
		ctx,
		userID,
		tokenEmailHash,
		refreshTokenHash,
	)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("verify email and add session: %w", err))
	}
	if user == nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("user not found: %w", errs.ErrNotFound))
	}

	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.tokens.CreateJWT(*user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	tokens, err := domain.NewTokens(accessToken, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}

	return *user, tokens, nil
}
