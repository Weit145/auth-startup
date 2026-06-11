package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type LoginService interface {
	Login(ctx context.Context, email, password string) (domain.User, domain.Tokens, error)
	Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error
}

func (s *Service) Login(ctx context.Context, email, password string) (domain.User, domain.Tokens, error) {
	account, err := s.repo.GetUserByEmail(ctx, email)
	if errors.Is(err, errs.ErrNotFound) {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("not found user: %w", errs.ErrUnauthorized))
	}
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("get user by email: %w", err))
	}
	user := account.User()

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	err = account.CheckVerifiedPassword(password)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("not verifiend password: %w", err))
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

	accessToken, err := s.tokens.CreateJWT(user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	result, err := s.repo.AddSession(ctx, user, refreshTokenHash)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("add session: %w", err))
	}
	tokens, err := domain.NewTokens(accessToken, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}
	return result, tokens, nil
}

func (s *Service) Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error {
	tokenRefreshDomain, err := domain.NewRefreshToken(refreshToken, nil)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	refreshTokenHash, err := s.tokens.HashRefreshToken(tokenRefreshDomain)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	err = s.repo.RevokeSession(ctx, userId, refreshTokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("logout: %w", err))
	}

	return nil
}
