package event

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

const EmailVerificationRequestedType = "email_verification_requested"

type EmailRequested struct {
	EventID         string    `json:"event_id"`
	Type            string    `json:"type"`
	UserID          string    `json:"user_id"`
	Email           string    `json:"email"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

func NewEmailVer(ctx context.Context, email domain.Email, confirmationURL string) (*EmailRequested, error) {
	if email.UserID() == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("userID is nil"))
	}

	if email.Email() == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email is empty"))
	}

	if email.Token() == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("token is empty"))
	}

	if email.ExpiresAt().IsZero() {
		return nil, logger.WrapError(ctx, fmt.Errorf("expiresAt is empty"))
	}

	verificationURL, err := url.Parse(confirmationURL)
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid confirmation URL: %q", confirmationURL))
	}
	query := verificationURL.Query()
	query.Set("token", email.Token())
	query.Set("userId", email.UserID().String())
	verificationURL.RawQuery = query.Encode()

	now := time.Now().UTC()

	return &EmailRequested{
		EventID:         uuid.NewString(),
		Type:            EmailVerificationRequestedType,
		UserID:          email.UserID().String(),
		Email:           email.Email(),
		VerificationURL: verificationURL.String(),
		ExpiresAt:       email.ExpiresAt(),
		CreatedAt:       now,
	}, nil
}
