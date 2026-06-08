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
	Register(ctx context.Context, email, password, name string) error
	Login(ctx context.Context, email, password string) (pb.AuthResponse, error)
	ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (pb.AuthResponse, error)
	Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error
	RefreshToken(ctx context.Context, refreshToken string) (pb.AuthResponse, error)
}

func (s *Service) Register(ctx context.Context, email, password, name string) error {
	user, err := domain.NewUser(ctx, email, password, name)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create domain user: %w", err))
	}

	token, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err))
	}

	tokenHash := s.inf.HashToken(token)
	tokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.EmailVerificationTokenTTL)

	result, err := s.repo.CreateUserWithEmailVerificationToken(ctx, *user, tokenHash, tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create user with email verification token: %w", err))
	}

	ctx = logger.WithLogID(ctx, result.ID())

	emailEvent, err := event.NewEmailVer(
		ctx, tokenExpiresAt,
		result.ID(), result.Email(),
		token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create event: %w", err))
	}

	err = s.notifications.PublishEmailVerificationRequested(ctx, *emailEvent)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("publish email: %w", err))
	}

	return nil
}

func (s *Service) Login(ctx context.Context, email, password string) (pb.AuthResponse, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("get user by email: %w", err))
	}
	if user == nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, errs.ErrNotFound)
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	err = user.CheckVerifiedPassword(ctx, password)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("compare password hash: %w", err))
	}

	refreshToken, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.RefreshTokenTTL)

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	result, err := s.repo.AddSession(ctx, *user, refreshTokenHash, refreshTokenExpiresAt)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("add session: %w", err))
	}

	return pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &pb.User{
			Id:       result.ID().String(),
			Email:    result.Email(),
			Username: result.Name(),
			Role:     result.Role(),
		},
	}, nil
}

func (s *Service) ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (pb.AuthResponse, error) {
	tokenHash := s.inf.HashToken(token)
	refreshToken, err := s.inf.CreateHashToken(ctx)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)
	refreshTokenExpiresAt := time.Now().UTC().Add(s.cfg.Time.RefreshTokenTTL)

	user, err := s.repo.VerifyEmailAndAddSession(
		ctx,
		userID,
		tokenHash,
		refreshTokenHash,
		refreshTokenExpiresAt,
	)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("verify email and add session: %w", err))
	}
	if user == nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, errs.ErrNotFound)
	}

	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	return pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &pb.User{
			Id:       user.ID().String(),
			Email:    user.Email(),
			Username: user.Name(),
			Role:     user.Role(),
		},
	}, nil
}

func (s *Service) Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error {
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)

	err := s.repo.RevokeSession(ctx, userId, refreshTokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("logout: %w", err))
	}

	return nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (pb.AuthResponse, error) {
	refreshTokenHash := s.inf.HashRefreshToken(refreshToken)

	user, err := s.repo.ValidateSession(ctx, refreshTokenHash)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("validate refresh session: %w", err))
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.inf.CreateJWT(ctx, user)
	if err != nil {
		return pb.AuthResponse{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	return pb.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: &pb.User{
			Id:       user.ID().String(),
			Email:    user.Email(),
			Username: user.Name(),
			Role:     user.Role(),
		},
	}, nil
}
