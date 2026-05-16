package mapper_err

import (
	"context"
	"errors"
	"log/slog"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Field struct {
	Name  string
	Value string
}

func MapErr(err error) (interface{}, error) {
	switch {
	case errors.Is(err, errs.ErrUnauthorized):
		return nil, status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, errs.ErrForbidden):
		return nil, status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, errs.ErrInvalidInput):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, errs.ErrNotFound):
		return nil, status.Error(codes.NotFound, err.Error())
	default:
		return nil, status.Error(codes.Internal, err.Error())
	}
}

func InvalidErr(ctx context.Context, fields ...Field) error {
	for _, field := range fields {
		if field.Value == "" {
			slog.DebugContext(ctx, "required field is empty", slog.String("field", field.Name))
			return status.Error(codes.InvalidArgument, field.Name+" is required")
		}
	}
	return nil
}
