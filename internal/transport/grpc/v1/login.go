package grpc

import (
	"context"
	"errors"
	"log/slog"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/transport/grpc/v1/mapper"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "email", Value: &email},
		mapper_err.Field{Name: "password", Value: &password},
	); err != nil {
		return nil, err
	}

	ctx = logger.WithLogEmail(ctx, email)

	user, tokens, err := s.ser.Login(ctx, email, password)
	if err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "login canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "login rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "login failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	authResp := mapper.MapDomainToAuthResponse(user, tokens)
	slog.InfoContext(ctx, "login successful")
	return authResp, nil
}

func (s *Server) Logout(ctx context.Context, req *pb.LogOutRequest) (*pb.Empty, error) {
	userID := req.GetUserID()
	refreshToken := req.GetRefreshToken()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "userID", Value: &userID},
		mapper_err.Field{Name: "refreshToken", Value: &refreshToken},
	); err != nil {
		return nil, err
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}
	ctx = logger.WithLogID(ctx, userUUID)

	if err := s.ser.Logout(ctx, userUUID, refreshToken); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)

		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "logout canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "logout rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "logout failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)

	}

	slog.InfoContext(ctx, "logout successful")

	return &pb.Empty{}, nil
}
