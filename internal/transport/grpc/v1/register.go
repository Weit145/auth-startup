package grpc

import (
	"context"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/transport/grpc/v1/mapper"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.Empty, error) {
	name := req.GetName()
	email := req.GetEmail()
	password := req.GetPassword()

	ctx = logger.WithLogEmail(ctx, email)
	ctx = logger.WithLogName(ctx, name)

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "name", Value: &name},
		mapper_err.Field{Name: "email", Value: &email},
		mapper_err.Field{Name: "password", Value: &password},
	); err != nil {
		slog.WarnContext(ctx, "register validation failed", slog.Any("error", err))
		return nil, err
	}

	err := s.ser.Register(ctx, email, password, name)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "register failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}

	slog.InfoContext(ctx, "register completed")

	return &pb.Empty{}, nil
}

func (s *Server) ConfirmEmail(ctx context.Context, req *pb.ConfirmRequest) (*pb.AuthResponse, error) {
	token := req.GetToken()
	userID := req.GetUserID()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "token", Value: &token},
		mapper_err.Field{Name: "userID", Value: &userID},
	); err != nil {
		slog.WarnContext(ctx, "login validation failed", slog.Any("error", err))
		return nil, err
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}

	ctx = logger.WithLogID(ctx, userUUID)

	user, tokens, err := s.ser.ConfirmEmail(ctx, token, userUUID)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "confirm email failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}
	authResp := mapper.MapDomainToAuthResponse(user, tokens)
	slog.InfoContext(ctx, "email confirmed")

	return authResp, nil
}
