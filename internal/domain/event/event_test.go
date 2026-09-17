package event_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/google/uuid"
)

func TestNewEvent(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidAt := time.Time{}

	token, err := domain.NewEmailVerificationToken(
		"valid",
		&expiresAt,
	)
	if err != nil {
		t.Errorf("create NewEmailVerificationToken")
	}
	userID := uuid.New()
	typeObj := event.EmailVerificationRequestedType
	cases := []struct {
		name            string
		email           string
		confirmationURL string
		token           domain.EmailVerificationToken
		expiresAt       time.Time
		userID          *uuid.UUID
		typeEventObj    event.TypeEvent
		waitErr         error
	}{
		{
			name:            "valid",
			email:           "test@example.com",
			confirmationURL: "http://example.com/verify",
			token:           token,
			expiresAt:       expiresAt,
			userID:          &userID,
			typeEventObj:    typeObj,
			waitErr:         nil,
		},
		{
			name:            "valid with nil userID",
			email:           "test@example.com",
			confirmationURL: "http://example.com/verify",
			token:           token,
			expiresAt:       expiresAt,
			userID:          nil,
			typeEventObj:    typeObj,
			waitErr:         nil,
		},
		{
			name:            "empty email",
			email:           "",
			confirmationURL: "http://example.com/verify",
			token:           token,
			expiresAt:       expiresAt,
			userID:          nil,
			typeEventObj:    typeObj,
			waitErr:         errs.ErrInvalidInput,
		},
		{
			name:            "invalid confirmation URL",
			email:           "test@example.com",
			confirmationURL: "asdasd",
			token:           token,
			expiresAt:       expiresAt,
			userID:          &userID,
			typeEventObj:    typeObj,
			waitErr:         errs.ErrInvalidInput,
		},
		{
			name:            "invalid token",
			email:           "test@example.com",
			confirmationURL: "http://example.com/verify",
			token:           domain.EmailVerificationToken{},
			expiresAt:       expiresAt,
			userID:          &userID,
			typeEventObj:    typeObj,
			waitErr:         errs.ErrInvalidInput,
		},
		{
			name:            "invalid expiresAt",
			email:           "test@example.com",
			confirmationURL: "http://example.com/verify",
			token:           token,
			expiresAt:       invalidAt,
			userID:          &userID,
			typeEventObj:    typeObj,
			waitErr:         errs.ErrInvalidInput,
		},
		{
			name:            "invalid typeEventObj",
			email:           "test@example.com",
			confirmationURL: "http://example.com/verify",
			token:           token,
			expiresAt:       expiresAt,
			userID:          &userID,
			typeEventObj:    event.TypeEvent{},
			waitErr:         errs.ErrInvalidInput,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ev, err := event.NewEvent(
				tc.email,
				tc.confirmationURL,
				tc.token,
				tc.expiresAt,
				tc.userID,
				tc.typeEventObj,
			)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("error new event: %v, wait %v",
					err,
					tc.waitErr,
				)
			}
			if err != nil {
				return
			}
			if ev.TypeEvent().String() != tc.typeEventObj.String() {
				t.Fatalf("invalid event type: %v",
					ev.TypeEvent().String(),
				)
			}
			if ev.UserID() != tc.userID {
				t.Fatalf("invalid event user ID: %v",
					ev.UserID(),
				)
			}
			if ev.Email() != tc.email {
				t.Fatalf("invalid event email: %v",
					ev.Email(),
				)
			}
			if ev.ExpiresAt() != tc.expiresAt {
				t.Fatalf("invalid event expiresAt: %v",
					ev.ExpiresAt(),
				)
			}
		})
	}
}
