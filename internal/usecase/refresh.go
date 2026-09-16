package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
)

func (s *Service) RefreshToken(
	ctx context.Context,
	refreshToken string,
) (domain.User, domain.Tokens, error) {
	tokenRefreshDomain, err := domain.NewRefreshToken(refreshToken, nil)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}

	tokenRefreshHash, err := s.tokens.HashRefreshToken(tokenRefreshDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	refreshTokenNew, err := s.tokens.CreateRefreshToken()
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshTokenHashNew, err := s.tokens.HashRefreshToken(refreshTokenNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	user, err := s.repo.RotateSession(ctx, tokenRefreshHash, refreshTokenHashNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("rotate refresh session: %w", err))
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.tokens.CreateJWT(user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	tokens, err := domain.NewTokens(accessToken, refreshTokenNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}
	return user, tokens, nil
}
