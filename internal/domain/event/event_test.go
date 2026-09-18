package event_test

import (
	"errors"
	"net/url"
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
			t.Parallel()
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

func TestRestoreEvent(t *testing.T) {
	eventID := uuid.New()
	userID := uuid.New()
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidAt := time.Time{}

	cases := []struct {
		name            string
		eventID         uuid.UUID
		typeEvent       string
		userID          *uuid.UUID
		email           string
		verificationURL string
		expiresAt       time.Time
		createdAt       time.Time
		waitError       error
	}{
		{
			name:            "valid",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          &userID,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       nil,
		},
		{
			name:            "valid",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       nil,
		},
		{
			name:            "invalid eventID",
			eventID:         uuid.Nil,
			typeEvent:       "email_verification_requested",
			userID:          nil,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       errs.ErrInvalidInput,
		},
		{
			name:            "invalid type event",
			eventID:         eventID,
			typeEvent:       "email",
			userID:          &userID,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       event.ErrInvalidType,
		},
		{
			name:            "invalid user id",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          &uuid.Nil,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       errs.ErrInvalidInput,
		},
		{
			name:            "invalid email",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          nil,
			email:           "test",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       errs.ErrInvalidInput,
		},
		{
			name:            "invalid verificationURL",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          &userID,
			email:           "test@example.com",
			verificationURL: "herify",
			expiresAt:       expiresAt,
			createdAt:       expiresAt,
			waitError:       errs.ErrInvalidInput,
		},
		{
			name:            "invalid expiresAt",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          &userID,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       invalidAt,
			createdAt:       expiresAt,
			waitError:       errs.ErrInvalidInput,
		},
		{
			name:            "invalid createdAt",
			eventID:         eventID,
			typeEvent:       "email_verification_requested",
			userID:          &userID,
			email:           "test@example.com",
			verificationURL: "http://example.com/verify",
			expiresAt:       expiresAt,
			createdAt:       invalidAt,
			waitError:       errs.ErrInvalidInput,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev, err := event.RestoreEvent(
				tc.eventID,
				tc.typeEvent,
				tc.userID,
				tc.email,
				tc.verificationURL,
				tc.expiresAt,
				tc.createdAt,
			)
			if !errors.Is(err, tc.waitError) {
				t.Fatalf(
					"error restore event: %v, wait %v",
					err,
					tc.waitError,
				)
			}
			if err != nil {
				return
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

func TestBindUserID(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	typeObj := event.EmailVerificationRequestedType

	token, err := domain.NewEmailVerificationToken(
		"valid",
		&expiresAt,
	)
	if err != nil {
		t.Errorf("create NewEmailVerificationToken")
	}
	userID := uuid.New()
	eve, err := event.NewEvent(
		"test@example.com",
		"http://example.com/verify",
		token,
		expiresAt,
		&userID,
		typeObj,
	)
	if err != nil {
		t.Errorf("create NewEvent")
	}
	cases := []struct {
		name      string
		eve       event.Event
		userID    uuid.UUID
		waitError error
	}{
		{
			name:      "valid",
			eve:       eve,
			userID:    userID,
			waitError: nil,
		},
		{
			name:      "invalid event",
			eve:       event.Event{},
			userID:    userID,
			waitError: errs.ErrInvalidInput,
		},
		{
			name:      "invalid userID",
			eve:       eve,
			userID:    uuid.Nil,
			waitError: errs.ErrInvalidInput,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.eve.BindUserID(tc.userID)
			if !errors.Is(err, tc.waitError) {
				t.Fatalf("error bind user id: %v, wait %v",
					err,
					tc.waitError,
				)
			}
			if err != nil {
				return
			}
			if tc.eve.UserID() == nil || *tc.eve.UserID() != tc.userID {
				t.Fatalf("invalid event user ID: %v, wait %v",
					tc.eve.UserID(),
					tc.userID,
				)
			}
			verificationURL, err := url.Parse(tc.eve.VerificationURL())
			if err != nil {
				t.Fatalf("parse verification URL: %v", err)
			}
			if got := verificationURL.Query().Get("userId"); got != tc.userID.String() {
				t.Fatalf("invalid userId in verification URL: %q, wait %q",
					got,
					tc.userID.String(),
				)
			}
		})
	}

}
