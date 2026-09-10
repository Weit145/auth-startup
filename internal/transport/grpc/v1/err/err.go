package mapper_err

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"strings"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Field struct {
	Name  string
	Value *string
}

func MapErr(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	case errors.Is(err, errs.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, "unauthorized")
	case errors.Is(err, errs.ErrForbidden):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, errs.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, "invalid input")
	case errors.Is(err, errs.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, errs.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, "already exists")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}

func ValidateInvalidErr(ctx context.Context, fields ...Field) error {
	for _, field := range fields {
		if field.Value == nil {
			slog.DebugContext(ctx, "required field is nil", slog.String("field", field.Name))
			return status.Error(codes.InvalidArgument, field.Name+" is required")
		}

		value := *field.Value
		if field.Name == "email" {
			value = strings.ToLower(value)
		}
		*field.Value = value

		if strings.TrimSpace(value) == "" {
			slog.DebugContext(ctx, "required field is empty", slog.String("field", field.Name))
			return status.Error(codes.InvalidArgument, field.Name+" is required")
		}

		if field.Name == "email" {
			address, err := mail.ParseAddress(value)
			if err != nil || address.Address != value {
				slog.DebugContext(ctx, "invalid email", slog.String("field", field.Name))
				return status.Error(codes.InvalidArgument, field.Name+" must be a valid email")
			}
		}
	}
	return nil
}
