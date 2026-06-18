package grpc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/transport/grpc/v1/mapper"
	pb "github.com/weit145/proto-startup/auth"
)

type RefreshService interface {
	RefreshToken(ctx context.Context, refreshToken string) (domain.User, domain.Tokens, error)
}

func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.AuthResponse, error) {
	refreshToken := req.GetRefreshToken()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "refreshToken", Value: &refreshToken},
	); err != nil {
		return nil, err
	}

	user, tokens, err := s.ser.RefreshToken(ctx, refreshToken)
	if err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "refresh token canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "refresh token rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "refresh token failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	authResp := mapper.MapDomainToAuthResponse(user, tokens)
	slog.InfoContext(ctx, "refresh token successful")
	return authResp, nil
}
