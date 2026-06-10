package domain

import (
	"context"
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/Weit145/auth-startup/internal/logger"
)

type Token struct {
	value     string
	expiresAt *time.Time
}

func (t Token) Value() string {
	return t.value
}

func (t Token) ExpiresAt() (time.Time, bool) {
	if t.expiresAt == nil {
		return time.Time{}, false
	}

	return *t.expiresAt, true
}

func (t *Token) CreateExpiresAt(tm time.Duration) {
	tokenExpiresAt := time.Now().UTC().Add(tm)
	t.expiresAt = &tokenExpiresAt
}

func (t Token) IsExpired() bool {
	if t.expiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*t.expiresAt)
}

func NewToken(ctx context.Context, tokenHash string, expiresAt *time.Time) (Token, error) {
	tokenHash, err := valid.ValidateOpaqueValue(ctx, tokenHash)
	if err != nil {
		return Token{}, logger.WrapError(ctx, fmt.Errorf("invalid token: %w", err))
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return Token{}, logger.WrapError(ctx, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput))
	}

	return Token{
		value:     tokenHash,
		expiresAt: expiresAt,
	}, nil
}

type Tokens struct {
	accessToken  Token
	refreshToken Token
}

func (t Tokens) AccessToken() Token {
	return t.accessToken
}

func (t Tokens) RefreshToken() Token {
	return t.refreshToken
}

func NewTokens(ctx context.Context, accessToken, refreshToken Token) (Tokens, error) {
	if _, err := valid.ValidateOpaqueValue(ctx, accessToken.Value()); err != nil {
		return Tokens{}, logger.WrapError(ctx, fmt.Errorf("invalid access token: %w", err))
	}

	if _, err := valid.ValidateOpaqueValue(ctx, refreshToken.Value()); err != nil {
		return Tokens{}, logger.WrapError(ctx, fmt.Errorf("invalid refresh token: %w", err))
	}

	return Tokens{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}, nil
}
