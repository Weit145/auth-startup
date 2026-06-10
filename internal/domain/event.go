package domain

import (
	"context"
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type Email struct {
	userID    uuid.UUID
	email     string
	token     string
	expiresAt time.Time
}

func (e Email) UserID() uuid.UUID {
	return e.userID
}

func (e Email) Email() string {
	return e.email
}

func (e Email) Token() string {
	return e.token
}

func (e Email) ExpiresAt() time.Time {
	return e.expiresAt
}

func NewEmail(ctx context.Context, userID uuid.UUID, email string, token Token, expiresAt time.Time) (Email, error) {
	if userID == uuid.Nil {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput))
	}

	email, err := valid.NormalizeEmail(ctx, email)
	if err != nil {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("invalid email: %w", err))
	}

	tokenValue, err := valid.ValidateOpaqueValue(ctx, token.Value())
	if err != nil {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("invalid token: %w", err))
	}

	if expiresAt.IsZero() {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput))
	}

	return Email{
		userID:    userID,
		email:     email,
		token:     tokenValue,
		expiresAt: expiresAt,
	}, nil
}
