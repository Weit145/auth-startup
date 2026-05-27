package event

import (
	"context"
	"fmt"
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

func NewEmailVer(ctx context.Context, expiresAt time.Time, userID uuid.UUID, email string, token string) (*EmailRequested, error) {
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

	now := time.Now().UTC()

	return &EmailRequested{
		EventID:         uuid.NewString(),
		Type:            EmailVerificationRequestedType,
		UserID:          userID.String(),
		Email:           email,
		VerificationURL: "https://your-domain.com/confirm-email?token=" + token + "&userId=" + userID.String(),
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
	}, nil
}
