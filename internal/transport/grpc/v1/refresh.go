package grpc

import (
	"context"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/transport/grpc/v1/mapper"
	pb "github.com/weit145/proto-startup/auth"
)

func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.AuthResponse, error) {
	refreshToken := req.GetRefreshToken()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "refreshToken", Value: &refreshToken},
	); err != nil {
		slog.WarnContext(ctx, "refresh token validation failed", slog.Any("error", err))
		return nil, err
	}

	user, tokens, err := s.ser.RefreshToken(ctx, refreshToken)
	if err != nil {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "refresh token failed", slog.Any("error", err))
		return nil, mapper_err.MapErr(err)
	}
	authResp := mapper.MapDomainToAuthResponse(user, tokens)
	slog.InfoContext(ctx, "refresh token successful")

	return authResp, nil
}
