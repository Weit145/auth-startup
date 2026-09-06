package dto

import (
	"errors"
	"strings"

	"github.com/Weit145/auth-startup/internal/domain/event"
)

var (
	ErrInvalidType = errors.New("invalid event type")
)

type TypeEvent struct {
	value string
}

func (t TypeEvent) String() string { return t.value }

var (
	EmailVerificationRequestedType = TypeEvent{value: "email_verification_requested"}
	ReapitEmailVerificationType    = TypeEvent{value: "reapit_email_verification"}
	ResetPasswordType              = TypeEvent{value: "reset_password"}
)

func ParseType(val string) (TypeEvent, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "email_verification_requested":
		return EmailVerificationRequestedType, nil
	case "reapit_email_verification":
		return ReapitEmailVerificationType, nil
	case "reset_password":
		return ResetPasswordType, nil
	default:
		return EmailVerificationRequestedType, ErrInvalidType
	}
}

func ParseDomainType(eventType event.TypeEvent) (TypeEvent, error) {
	switch eventType {
	case event.EmailVerificationRequestedType:
		return EmailVerificationRequestedType, nil
	case event.ReapitEmailVerificationType:
		return ReapitEmailVerificationType, nil
	case event.ResetPasswordType:
		return ResetPasswordType, nil
	default:
		return EmailVerificationRequestedType, ErrInvalidType
	}
}
