package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/logger"
)

type Token struct {
	value     string
	expiresAt *time.Time
}

type Tokens struct {
	accessToken  Token
	refreshToken Token
}

func NewToken(ctx context.Context, tokenHash string, expiresAt *time.Time) (Token, error) {
	if tokenHash == "" {
		return Token{}, logger.WrapError(ctx, fmt.Errorf("token hash cannot be empty"))
	}

	return Token{
		value:     tokenHash,
		expiresAt: expiresAt,
	}, nil
}

func NewTokens(ctx context.Context, accessToken, refreshToken Token) (Tokens, error) {
	if accessToken.Value() == "" {
		return Tokens{}, logger.WrapError(ctx, fmt.Errorf("access token cannot be empty"))
	}

	if refreshToken.Value() == "" {
		return Tokens{}, logger.WrapError(ctx, fmt.Errorf("refresh token cannot be empty"))
	}

	return Tokens{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}, nil
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

func (t Tokens) AccessToken() Token {
	return t.accessToken
}

func (t Tokens) RefreshToken() Token {
	return t.refreshToken
}
