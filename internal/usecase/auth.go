package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	pb "github.com/weit145/proto-startup/auth"
	"golang.org/x/crypto/bcrypt"
)

const refreshTokenTTL = 30 * 24 * time.Hour

type AuthService interface {
	Register(ctx context.Context, email, password, name string) (error, pb.AuthResponse)
	Login(ctx context.Context, email, password string) (error, pb.AuthResponse)
}

func (s *Service) Register(ctx context.Context, email, password, name string) (error, pb.AuthResponse) {
	user, err := domain.NewUser(email, name)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create domain user: %w", err)), pb.AuthResponse{}
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash password: %w", err)), pb.AuthResponse{}
	}

	refreshToken, err := s.inf.CreateRefreshToken()
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err)), pb.AuthResponse{}
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(refreshTokenTTL)

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create access token: %w", err)), pb.AuthResponse{}
	}

	result, err := s.repo.CreateUser(ctx, *user, string(passwordHash), refreshTokenHash, refreshTokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create user: %w", err)), pb.AuthResponse{}
	}

	ctx = logger.WithLogID(ctx, result.ID())

	return nil, pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &pb.User{
			Id:       result.ID().String(),
			Email:    result.Email(),
			Username: result.Name(),
			Role:     result.Role(),
		},
	}
}

func (s *Service) Login(ctx context.Context, email, password string) (error, pb.AuthResponse) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("get user by email: %w", err)), pb.AuthResponse{}
	}
	if user == nil {
		return logger.WrapError(ctx, errs.ErrNotFound), pb.AuthResponse{}
	}

	ctx = logger.WithLogID(ctx, user.ID())

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash()), []byte(password))
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("compare password hash: %w", errs.ErrUnauthorized)), pb.AuthResponse{}
	}

	refreshToken, err := s.inf.CreateRefreshToken()
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err)), pb.AuthResponse{}
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(refreshTokenTTL)

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create access token: %w", err)), pb.AuthResponse{}
	}

	result, err := s.repo.AddSession(ctx, *user, refreshTokenHash, refreshTokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("add session: %w", err)), pb.AuthResponse{}
	}

	return nil, pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &pb.User{
			Id:       result.ID().String(),
			Email:    result.Email(),
			Username: result.Name(),
			Role:     result.Role(),
		},
	}
}
