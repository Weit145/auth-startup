package dto

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type EmailRequested struct {
	EventID         string    `json:"event_id"`
	Type            TypeEvent `json:"type"`
	UserID          string    `json:"user_id"`
	Email           string    `json:"email"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

func NewEmailRequested(ctx context.Context, evt event.Event) (*EmailRequested, error) {
	if evt.EventID() == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("eventID is empty"))
	}
	if evt.UserID() == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("userID is nil"))
	}

	if evt.Email() == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email is empty"))
	}

	if evt.ExpiresAt().IsZero() {
		return nil, logger.WrapError(ctx, fmt.Errorf("expiresAt is empty"))
	}

	if evt.CreatedAt().IsZero() {
		return nil, logger.WrapError(ctx, fmt.Errorf("createdAt is empty"))
	}

	verificationURL, err := url.Parse(evt.VerificationURL())
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid verification URL: %w", err))
	}

	eventType, err := ParseDomainType(evt.TypeEvent())
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid event type: %w", err))
	}

	return &EmailRequested{
		EventID:         evt.EventID().String(),
		Type:            eventType,
		UserID:          evt.UserID().String(),
		Email:           evt.Email(),
		VerificationURL: evt.VerificationURL(),
		ExpiresAt:       evt.ExpiresAt(),
		CreatedAt:       evt.CreatedAt(),
	}, nil
}
