package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/event"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
)

type AuthService interface {
	Register(ctx context.Context, email, password, name string) (error, pb.Health)
	Login(ctx context.Context, email, password string) (error, pb.AuthResponse)
	ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (error, pb.AuthResponse)
}

func (s *Service) Register(ctx context.Context, email, password, name string) (error, pb.Health) {
	user, err := domain.NewUser(ctx, email, password, name)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create domain user: %w", err)), pb.Health{Health: false}
	}

	token, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err)), pb.Health{Health: false}
	}

	tokenHash := s.inf.HashToken(token)
	tokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.EmailVerificationTokenTTL)

	result, err := s.repo.CreateUserWithEmailVerificationToken(ctx, *user, tokenHash, tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create user with email verification token: %w", err)), pb.Health{Health: false}
	}

	ctx = logger.WithLogID(ctx, result.ID())

	emailEvent, err := event.NewEmailVer(
		ctx, tokenExpiresAt,
		result.ID(), result.Email(),
		token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create event: %w", err)), pb.Health{Health: false}
	}

	err = s.notifications.PublishEmailVerificationRequested(ctx, *emailEvent)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("publish email: %w", err)), pb.Health{Health: false}
	}

	return nil, pb.Health{Health: true}
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
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	err = user.CheckVerifiedPassword(ctx, password)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("compare password hash: %w", err)), pb.AuthResponse{}
	}

	refreshToken, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err)), pb.AuthResponse{}
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.RefreshTokenTTL)

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

func (s *Service) ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (error, pb.AuthResponse) {
	tokenHash := s.inf.HashToken(token)
	user, err := s.repo.VerifyEmail(ctx, userID, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("verify email: %w", err)), pb.AuthResponse{}
	}
	if user == nil {
		return logger.WrapError(ctx, errs.ErrNotFound), pb.AuthResponse{}
	}

	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	refreshToken, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err)), pb.AuthResponse{}
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.RefreshTokenTTL)

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
