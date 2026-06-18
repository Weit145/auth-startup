package grpc

import (
	"context"
	"errors"
	"log/slog"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PasswordService interface {
	PasswordRequest(ctx context.Context, email string) error
	PasswordConfirm(ctx context.Context, userID uuid.UUID, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
}

func (s *Server) PasswordRequest(ctx context.Context, req *pb.Email) (*pb.Empty, error) {
	email := req.GetEmail()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "email", Value: &email},
	); err != nil {
		return nil, err
	}

	ctx = logger.WithLogEmail(ctx, email)

	if err := s.ser.PasswordRequest(ctx, email); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "email repeat canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "email repeat rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "email repeat failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	return &pb.Empty{}, nil
}

func (s *Server) PasswordConfirm(ctx context.Context, req *pb.PasswordConfirmRequest) (*pb.Empty, error) {
	userID := req.GetUserID()
	token := req.GetToken()
	newPassword := req.GetNewPassword()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "userID", Value: &userID},
		mapper_err.Field{Name: "token", Value: &token},
		mapper_err.Field{Name: "newPassword", Value: &newPassword},
	); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}

	ctx = logger.WithLogID(ctx, id)

	if err := s.ser.PasswordConfirm(ctx, id, token, newPassword); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "email repeat canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "email repeat rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "email repeat failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	return &pb.Empty{}, nil
}

func (s *Server) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.Empty, error) {
	userID := req.GetUserID()
	newPassword := req.GetNewPassword()
	oldPassword := req.GetOldPassword()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "userID", Value: &userID},
		mapper_err.Field{Name: "oldPassword", Value: &oldPassword},
		mapper_err.Field{Name: "newPassword", Value: &newPassword},
	); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}

	ctx = logger.WithLogID(ctx, id)

	if err := s.ser.ChangePassword(ctx, id, oldPassword, newPassword); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "email repeat canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "email repeat rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "email repeat failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	return &pb.Empty{}, nil
}
