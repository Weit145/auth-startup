package v1

import (
	"context"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/usecase"
	pb "github.com/Weit145/proto-startup/auth"
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

func (s *Server) CheckHealth(ctx context.Context, req *pb.Empty) (*pb.Health, error) {

	err := s.ser.CheckHealth(ctx)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "health check failed", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "failed to check health")
	}

	resp := pb.Health{Health: true}
	return &resp, nil
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
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

	err, authResp := s.ser.Register(ctx, email, password, name)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "register failed", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "failed to register user")
	}
	if authResp.User == nil {
		slog.ErrorContext(ctx, "register returned empty user")
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	slog.InfoContext(ctx, "register completed", slog.String("user_id", authResp.User.Id))

	return &pb.AuthResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		User: &pb.User{
			Id:       authResp.User.Id,
			Email:    authResp.User.Email,
			Username: authResp.User.Username,
			Role:     authResp.User.Role,
		},
	}, nil
}
