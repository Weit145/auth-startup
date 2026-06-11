package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/usecase"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type Setting struct {
	TLSCertPEM     []byte
	TLSKeyPEM      []byte
	TLSClientCAPEM []byte
}

type Server struct {
	pb.UnimplementedAuthServer
	ser usecase.Services
}

func NewServer(ser usecase.Services, setting Setting) (*grpc.Server, error) {
	clientCAs, err := ClientCertPool(setting.TLSClientCAPEM)
	if err != nil {
		return nil, err
	}

	certificate, err := ServerCertificate(setting.TLSCertPEM, setting.TLSKeyPEM)
	if err != nil {
		return nil, err
	}

	tc := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	s := grpc.NewServer(grpc.Creds(tc))
	pb.RegisterAuthServer(s, &Server{ser: ser})
	return s, nil
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

func ClientCertPool(clientCAPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	if ok := pool.AppendCertsFromPEM(clientCAPEM); !ok {
		return nil, fmt.Errorf("parse gRPC client CA certificate")
	}

	return pool, nil
}

func ServerCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse gRPC server certificate: %w", err)
	}

	return certificate, nil
}
