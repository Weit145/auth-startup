package v1

import (
	"context"

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
		return nil, status.Error(codes.Internal, "failed to check health")
	}

	resp := pb.Health{Health: true}
	return &resp, nil
}
