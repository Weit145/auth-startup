package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type Email struct {
	userID    uuid.UUID
	email     string
	token     string
	expiresAt time.Time
}

func NewEmail(ctx context.Context, userID uuid.UUID, email string, token Token, expiresAt time.Time) (Email, error) {
	if userID == uuid.Nil {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("userID is nil"))
	}
	if email == "" {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("email is empty"))
	}
	if token.Value() == "" {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("token is empty"))
	}
	if expiresAt.IsZero() {
		return Email{}, logger.WrapError(ctx, fmt.Errorf("expiresAt is empty"))
	}

	return Email{
		userID:    userID,
		email:     email,
		token:     token.Value(),
		expiresAt: expiresAt,
	}, nil
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
