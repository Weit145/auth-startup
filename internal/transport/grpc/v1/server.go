package grpc

import (
	"context"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/usecase"
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
