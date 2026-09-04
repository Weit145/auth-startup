package domain

import (
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/google/uuid"
)

type Email struct {
	userID    uuid.UUID
	email     string
	token     string
	expiresAt time.Time
}

func (e Email) UserID() uuid.UUID    { return e.userID }
func (e Email) Email() string        { return e.email }
func (e Email) Token() string        { return e.token }
func (e Email) ExpiresAt() time.Time { return e.expiresAt }

func NewEmail(userID uuid.UUID, email string, token EmailVerificationToken, expiresAt time.Time) (Email, error) {
	if userID == uuid.Nil {
		return Email{}, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput)
	}

	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return Email{}, fmt.Errorf("invalid email: %w", err)
	}

	tokenValue, err := valid.ValidateOpaqueValue(token.Value())
	if err != nil {
		return Email{}, fmt.Errorf("invalid token: %w", err)
	}

	if expiresAt.IsZero() {
		return Email{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	return Email{
		userID:    userID,
		email:     email,
		token:     tokenValue,
		expiresAt: expiresAt,
	}, nil
}
