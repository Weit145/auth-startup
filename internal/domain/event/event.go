package event

import (
	"fmt"
	"net/url"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/google/uuid"
)

type Event struct {
	eventID         uuid.UUID
	typeEvent       TypeEvent
	userID          *uuid.UUID
	email           string
	verificationURL string
	expiresAt       time.Time
	createdAt       time.Time
}

func NewEvent(
	email, confirmationURL string,
	token domain.EmailVerificationToken,
	expiresAt time.Time,
	userID *uuid.UUID,
	typeEventObj TypeEvent,
) (Event, error) {
	if _, err := ParseType(typeEventObj.String()); err != nil {
		return Event{}, fmt.Errorf("invalid typeEvent %q: %w", typeEventObj.String(), errs.ErrInvalidInput)
	}
	if token.Value() == "" {
		return Event{}, fmt.Errorf("invalid token: %w", errs.ErrInvalidInput)
	}
	if userID != nil && *userID == uuid.Nil {
		return Event{}, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput)
	}
	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return Event{}, fmt.Errorf("invalid email: %w", err)
	}
	if confirmationURL == "" {
		return Event{}, fmt.Errorf("invalid verificationURL: %w", errs.ErrInvalidInput)
	}
	if expiresAt.IsZero() {
		return Event{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	verificationURL, err := url.Parse(confirmationURL)
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return Event{}, fmt.Errorf("invalid confirmation URL: %q: %w", confirmationURL, errs.ErrInvalidInput)
	}
	query := verificationURL.Query()
	query.Set("token", token.Value())
	if userID != nil {
		query.Set("userId", userID.String())
	}
	verificationURL.RawQuery = query.Encode()

	now := time.Now().UTC()

	return Event{
		eventID:         uuid.New(),
		typeEvent:       typeEventObj,
		userID:          userID,
		email:           email,
		verificationURL: verificationURL.String(),
		expiresAt:       expiresAt,
		createdAt:       now,
	}, nil
}

func RestoreEvent(
	eventID uuid.UUID,
	typeEvent string,
	userID *uuid.UUID,
	email string,
	verificationURL string,
	expiresAt time.Time,
	createdAt time.Time,
) (Event, error) {
	if eventID == uuid.Nil {
		return Event{}, fmt.Errorf("invalid eventID: %w", errs.ErrInvalidInput)
	}

	typeEventObj, err := ParseType(typeEvent)
	if err != nil {
		return Event{}, fmt.Errorf("invalid typeEvent %q: %w", typeEvent, err)
	}
	if userID != nil && *userID == uuid.Nil {
		return Event{}, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput)
	}
	email, err = valid.NormalizeEmail(email)
	if err != nil {
		return Event{}, fmt.Errorf("invalid email: %w", err)
	}
	if verificationURL == "" {
		return Event{}, fmt.Errorf("invalid verificationURL: %w", errs.ErrInvalidInput)
	}

	parsedVerificationURL, err := url.Parse(verificationURL)
	if err != nil || parsedVerificationURL.Scheme == "" || parsedVerificationURL.Host == "" {
		return Event{}, fmt.Errorf("invalid verification URL: %q: %w", verificationURL, errs.ErrInvalidInput)
	}
	if expiresAt.IsZero() {
		return Event{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}
	if createdAt.IsZero() {
		return Event{}, fmt.Errorf("invalid createdAt: %w", errs.ErrInvalidInput)
	}

	return Event{
		eventID:         eventID,
		typeEvent:       typeEventObj,
		userID:          userID,
		email:           email,
		verificationURL: parsedVerificationURL.String(),
		expiresAt:       expiresAt,
		createdAt:       createdAt,
	}, nil
}

func (e *Event) BindUserID(userID uuid.UUID) error {
	if userID == uuid.Nil {
		return fmt.Errorf("userID is empty %w", errs.ErrInvalidInput)
	}

	verificationURL, err := url.Parse(e.verificationURL)
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return fmt.Errorf("invalid verification URL: %q: %w", e.verificationURL, errs.ErrInvalidInput)
	}

	query := verificationURL.Query()
	query.Set("userId", userID.String())
	verificationURL.RawQuery = query.Encode()

	e.userID = &userID
	e.verificationURL = verificationURL.String()
	return nil
}

func (e Event) EventID() uuid.UUID      { return e.eventID }
func (e Event) TypeEvent() TypeEvent    { return e.typeEvent }
func (e Event) UserID() *uuid.UUID      { return e.userID }
func (e Event) Email() string           { return e.email }
func (e Event) VerificationURL() string { return e.verificationURL }
func (e Event) ExpiresAt() time.Time    { return e.expiresAt }
func (e Event) CreatedAt() time.Time    { return e.createdAt }
