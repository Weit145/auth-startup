package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
)

type RefreshService interface {
	RefreshToken(ctx context.Context, refreshToken string) (domain.User, domain.Tokens, error)
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (domain.User, domain.Tokens, error) {
	tokenDomain, err := domain.NewToken(ctx, refreshToken, nil)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}

	refreshTokenHash, err := s.tokens.HashToken(ctx, tokenDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	refreshTokenNew, err := s.tokens.CreateToken(ctx)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshTokenHashNew, err := s.tokens.HashToken(ctx, refreshTokenNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	user, err := s.repo.RotateSession(ctx, refreshTokenHash, refreshTokenHashNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("rotate refresh session: %w", err))
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.tokens.CreateJWT(ctx, user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	tokens, err := domain.NewTokens(ctx, accessToken, refreshTokenNew)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}
	return user, tokens, nil
}
