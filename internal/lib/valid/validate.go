package valid

import (
	"context"
	"net/mail"
	"strings"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
)

func NormalizeValue(ctx context.Context, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", logger.WrapError(ctx, errs.ErrInvalidInput)
	}
	return value, nil
}

func NormalizeEmail(ctx context.Context, email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return "", logger.WrapError(ctx, errs.ErrInvalidInput)
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", logger.WrapError(ctx, errs.ErrInvalidInput)
	}
	return email, nil
}

func NormalizePassword(ctx context.Context, password string) (string, error) {
	if strings.TrimSpace(password) == "" || len(password) < 8 || len(password) > 72 {
		return "", logger.WrapError(ctx, errs.ErrInvalidInput)
	}
	return password, nil
}

func ValidateOpaqueValue(ctx context.Context, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", logger.WrapError(ctx, errs.ErrInvalidInput)
	}
	return value, nil
}
