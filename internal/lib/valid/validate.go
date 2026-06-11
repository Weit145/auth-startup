package valid

import (
	"net/mail"
	"strings"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
)

func NormalizeValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errs.ErrInvalidInput
	}
	return value, nil
}

func NormalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return "", errs.ErrInvalidInput
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", errs.ErrInvalidInput
	}
	return email, nil
}

func NormalizePassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" || len(password) < 6 || len(password) > 72 {
		return "", errs.ErrInvalidInput
	}
	return password, nil
}

func ValidateOpaqueValue(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errs.ErrInvalidInput
	}
	return value, nil
}
