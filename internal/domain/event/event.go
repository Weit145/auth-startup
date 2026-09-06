package event

import (
	"fmt"
	"net/url"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/google/uuid"
)

type Event struct {
	eventID         uuid.UUID
	typeEvent       TypeEvent
	userID          uuid.UUID
	email           string
	verificationURL string
	expiresAt       time.Time
	createdAt       time.Time
}

func NewEvent(email, confirmationURL string, token domain.EmailVerificationToken, expiresAt time.Time, userID uuid.UUID, typeEventObj TypeEvent) (Event, error) {
	if email == "" {
		return Event{}, fmt.Errorf("invalid email: %w", errs.ErrInvalidInput)
	}
	if userID == uuid.Nil {
		return Event{}, fmt.Errorf("invalid userID: %w", errs.ErrInvalidInput)
	}

	if confirmationURL == "" {
		return Event{}, fmt.Errorf("invalid verificationURL: %w", errs.ErrInvalidInput)
	}
	if expiresAt.IsZero() {
		return Event{}, fmt.Errorf("invalid expiresAt: %w", errs.ErrInvalidInput)
	}

	verificationURL, err := url.Parse(confirmationURL)
	if err != nil || verificationURL.Scheme == "" || verificationURL.Host == "" {
		return Event{}, fmt.Errorf("invalid confirmation URL: %q", confirmationURL)
	}
	query := verificationURL.Query()
	query.Set("token", token.Value())
	query.Set("userId", userID.String())
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

func (e Event) EventID() uuid.UUID      { return e.eventID }
func (e Event) TypeEvent() TypeEvent    { return e.typeEvent }
func (e Event) UserID() uuid.UUID       { return e.userID }
func (e Event) Email() string           { return e.email }
func (e Event) VerificationURL() string { return e.verificationURL }
func (e Event) ExpiresAt() time.Time    { return e.expiresAt }
func (e Event) CreatedAt() time.Time    { return e.createdAt }
