package v1

import (
	"context"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/usecase"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedAuthServer
	ser usecase.Services
}

func NewServer(ser usecase.Services) *grpc.Server {
	s := grpc.NewServer()
	pb.RegisterAuthServer(s, &Server{ser: ser})

	return s
}

func (s *Server) CheckHealth(ctx context.Context, req *pb.Empty) (*pb.HealthDB, error) {

	bd, err := s.ser.CheckHealth(ctx)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "health check failed", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "failed to check health")
	}

	resp := &pb.HealthDB{
		Health: bd,
	}
	return resp, nil
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.Empty, error) {
	name := req.GetName()
	email := req.GetEmail()
	password := req.GetPassword()

	ctx = logger.WithLogEmail(ctx, email)
	ctx = logger.WithLogName(ctx, name)

	if err := mapper_err.InvalidErr(ctx,
		mapper_err.Field{Name: "name", Value: name},
		mapper_err.Field{Name: "email", Value: email},
		mapper_err.Field{Name: "password", Value: password},
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

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()
	ctx = logger.WithLogEmail(ctx, email)

	if err := mapper_err.InvalidErr(ctx,
		mapper_err.Field{Name: "email", Value: email},
		mapper_err.Field{Name: "password", Value: password},
	); err != nil {
		slog.WarnContext(ctx, "login validation failed", slog.Any("error", err))
		return nil, err
	}

	authResp, err := s.ser.Login(ctx, email, password)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "login failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}
	slog.InfoContext(ctx, "login successful")

	return &authResp, nil
}

func (s *Server) ConfirmEmail(ctx context.Context, req *pb.ConfirmRequest) (*pb.AuthResponse, error) {
	token := req.GetToken()
	userID := req.GetUserID()

	if err := mapper_err.InvalidErr(ctx,
		mapper_err.Field{Name: "token", Value: token},
		mapper_err.Field{Name: "userID", Value: userID},
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

	authResp, err := s.ser.ConfirmEmail(ctx, token, userUUID)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "confirm email failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}

	slog.InfoContext(ctx, "email confirmed")

	return &authResp, nil
}

func (s *Server) Logout(ctx context.Context, req *pb.LogOutRequest) (*pb.Empty, error) {
	userID := req.GetUserID()
	refreshToken := req.GetRefreshToken()

	if err := mapper_err.InvalidErr(ctx,
		mapper_err.Field{Name: "userID", Value: userID},
		mapper_err.Field{Name: "refreshToken", Value: refreshToken},
	); err != nil {
		slog.WarnContext(ctx, "logout validation failed", slog.Any("error", err))
		return nil, err
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}

	ctx = logger.WithLogID(ctx, userUUID)

	err = s.ser.Logout(ctx, userUUID, refreshToken)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "logout failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}

	slog.InfoContext(ctx, "logout successful")

	return &pb.Empty{}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.AuthResponse, error) {
	refreshToken := req.GetRefreshToken()

	if err := mapper_err.InvalidErr(ctx,
		mapper_err.Field{Name: "refreshToken", Value: refreshToken},
	); err != nil {
		slog.WarnContext(ctx, "refresh token validation failed", slog.Any("error", err))
		return nil, err
	}

	authResp, err := s.ser.RefreshToken(ctx, refreshToken)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "refresh token failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}
	slog.InfoContext(ctx, "refresh token successful")

	return &authResp, nil
}
