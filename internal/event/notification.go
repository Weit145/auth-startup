package event

import (
	"context"
	"fmt"
	"net/url"
	"time"

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

func NewEmailVer(ctx context.Context, expiresAt time.Time, userID uuid.UUID, email string, token string, confirmationURL string) (*EmailRequested, error) {
	if userID == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("userID is nil"))
	}

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email is empty"))
	}

	if token == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("token is empty"))
	}

	if expiresAt.IsZero() {
		return nil, logger.WrapError(ctx, fmt.Errorf("expiresAt is empty"))
	}

	verificationURL, err := url.Parse(confirmationURL)
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid confirmation URL: %q", confirmationURL))
	}
	query := verificationURL.Query()
	query.Set("token", token)
	query.Set("userId", userID.String())
	verificationURL.RawQuery = query.Encode()

	now := time.Now().UTC()

	return &EmailRequested{
		EventID:         uuid.NewString(),
		Type:            EmailVerificationRequestedType,
		UserID:          userID.String(),
		Email:           email,
		VerificationURL: verificationURL.String(),
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}, nil
}
