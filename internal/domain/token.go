package domain

import (
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/google/uuid"
)

type token struct {
	value     string
	expiresAt *time.Time
}

func (t token) Value() string { return t.value }
func (t token) ExpiresAt() (time.Time, bool) {
	if t.expiresAt == nil {
		return time.Time{}, false
	}
	return *t.expiresAt, true
}

func (t *token) CreateExpiresAt(tm time.Duration) {
	tokenExpiresAt := time.Now().UTC().Add(tm)
	t.expiresAt = &tokenExpiresAt
}

func (t token) IsExpired() bool {
	if t.expiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*t.expiresAt)
}

type AccessToken struct {
	token
}

func NewAccessToken(value string, expiresAt *time.Time) (AccessToken, error) {
	value, err := valid.ValidateOpaqueValue(value)
	if err != nil {
		return AccessToken{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return AccessToken{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return AccessToken{
		token: token{
			value:     value,
			expiresAt: expiresAt,
		},
	}, nil
}

type RefreshToken struct {
	token
}

func NewRefreshToken(value string, expiresAt *time.Time) (RefreshToken, error) {
	value, err := valid.ValidateOpaqueValue(value)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return RefreshToken{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return RefreshToken{
		token: token{
			value:     value,
			expiresAt: expiresAt,
		},
	}, nil
}

type RefreshTokenHash struct {
	token
}

func NewRefreshTokenHash(hash string, expiresAt *time.Time) (RefreshTokenHash, error) {
	hash, err := valid.ValidateOpaqueValue(hash)
	if err != nil {
		return RefreshTokenHash{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return RefreshTokenHash{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return RefreshTokenHash{
		token: token{
			value:     hash,
			expiresAt: expiresAt,
		},
	}, nil
}

type EmailVerificationToken struct {
	token
}

func NewEmailVerificationToken(value string, expiresAt *time.Time) (EmailVerificationToken, error) {
	value, err := valid.ValidateOpaqueValue(value)
	if err != nil {
		return EmailVerificationToken{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return EmailVerificationToken{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return EmailVerificationToken{
		token: token{
			value:     value,
			expiresAt: expiresAt,
		},
	}, nil
}

type EmailVerificationTokenHash struct {
	token
}

func NewEmailVerificationTokenHash(hash string, expiresAt *time.Time) (EmailVerificationTokenHash, error) {
	hash, err := valid.ValidateOpaqueValue(hash)
	if err != nil {
		return EmailVerificationTokenHash{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return EmailVerificationTokenHash{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return EmailVerificationTokenHash{
		token: token{
			value:     hash,
			expiresAt: expiresAt,
		},
	}, nil
}

type ShortSessionToken struct {
	id uuid.UUID
	token
}

func NewShortSessionToken(value string, expiresAt *time.Time) (ShortSessionToken, error) {
	value, err := valid.ValidateOpaqueValue(value)
	if err != nil {
		return ShortSessionToken{}, fmt.Errorf("invalid token: %w", err)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return ShortSessionToken{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return ShortSessionToken{
		id: uuid.New(),
		token: token{
			value:     value,
			expiresAt: expiresAt,
		},
	}, nil
}

func (t ShortSessionToken) ID() uuid.UUID { return t.id }

type ShortSessionTokenHash struct {
	id uuid.UUID
	token
}

func NewShortSessionTokenHash(id uuid.UUID, hash string, expiresAt *time.Time) (ShortSessionTokenHash, error) {
	hash, err := valid.ValidateOpaqueValue(hash)
	if err != nil {
		return ShortSessionTokenHash{}, fmt.Errorf("invalid token: %w", err)
	}
	if id == uuid.Nil {
		return ShortSessionTokenHash{}, fmt.Errorf("invalid id: %w", errs.ErrInvalidInput)
	}
	if expiresAt != nil && expiresAt.IsZero() {
		return ShortSessionTokenHash{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}
	return ShortSessionTokenHash{
		id: id,
		token: token{
			value:     hash,
			expiresAt: expiresAt,
		},
	}, nil
}

func (t ShortSessionTokenHash) ID() uuid.UUID { return t.id }

type Tokens struct {
	accessToken  AccessToken
	refreshToken RefreshToken
}

func (t Tokens) AccessToken() AccessToken   { return t.accessToken }
func (t Tokens) RefreshToken() RefreshToken { return t.refreshToken }

func NewTokens(accessToken AccessToken, refreshToken RefreshToken) (Tokens, error) {
	if _, err := valid.ValidateOpaqueValue(accessToken.Value()); err != nil {
		return Tokens{}, fmt.Errorf("invalid access token: %w", err)
	}

	if _, err := valid.ValidateOpaqueValue(refreshToken.Value()); err != nil {
		return Tokens{}, fmt.Errorf("invalid refresh token: %w", err)
	}

	return Tokens{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}, nil
}
