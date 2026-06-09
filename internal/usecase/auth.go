package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

type AuthService interface {
	Register(ctx context.Context, email, password, name string) error
	Login(ctx context.Context, email, password string) (domain.User, domain.Tokens, error)
	ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.User, domain.Tokens, error)
	Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error
	RefreshToken(ctx context.Context, refreshToken string) (domain.User, domain.Tokens, error)
}

func (s *Service) Register(ctx context.Context, email, password, name string) error {
	user, err := domain.NewUser(ctx, email, password, name)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create domain user: %w", err))
	}

	token, err := s.inf.CreateToken(ctx)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err))
	}
	token.CreateExpiresAt(s.cfg.Time.EmailVerificationTokenTTL)
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tokenHash, err := s.inf.HashToken(ctx, token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash token for email verification: %w", err))
	}

	result, err := s.repo.CreateUserWithEmailVerificationToken(ctx, *user, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create user with email verification token: %w", err))
	}
	ctx = logger.WithLogID(ctx, result.ID())

	emailEvent, err := domain.NewEmail(ctx, result.ID(), result.Email(), token, tokenExpiresAt)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
	}

	err = s.notifications.PublishEvent(ctx, emailEvent, s.cfg.Notification.EmailVerificationURL)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("publish email: %w", err))
	}

	return nil
}

func (s *Service) Login(ctx context.Context, email, password string) (domain.User, domain.Tokens, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("get user by email: %w", err))
	}
	if user == nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, errs.ErrNotFound)
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	err = user.CheckVerifiedPassword(ctx, password)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("compare password hash: %w", err))
	}

	refreshToken, err := s.inf.CreateToken(ctx)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshToken.CreateExpiresAt(s.cfg.Time.RefreshTokenTTL)
	refreshTokenHash, err := s.inf.HashToken(ctx, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	result, err := s.repo.AddSession(ctx, *user, refreshTokenHash)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("add session: %w", err))
	}
	tokens, err := domain.NewTokens(ctx, accessToken, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}
	return result, tokens, nil
}

func (s *Service) ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.User, domain.Tokens, error) {
	tokenDomain, err := domain.NewToken(ctx, token, nil)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	tokenHash, err := s.inf.HashToken(ctx, tokenDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash email verification token: %w", err))
	}
	refreshToken, err := s.inf.CreateToken(ctx)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshToken.CreateExpiresAt(s.cfg.Time.RefreshTokenTTL)
	refreshTokenHash, err := s.inf.HashToken(ctx, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}
	user, err := s.repo.VerifyEmailAndAddSession(
		ctx,
		userID,
		tokenHash,
		refreshTokenHash,
	)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("verify email and add session: %w", err))
	}
	if user == nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, errs.ErrNotFound)
	}

	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.inf.CreateJWT(ctx, *user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	tokens, err := domain.NewTokens(ctx, accessToken, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}

	return *user, tokens, nil
}

func (s *Service) Logout(ctx context.Context, userId uuid.UUID, refreshToken string) error {
	tokenDomain, err := domain.NewToken(ctx, refreshToken, nil)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	refreshTokenHash, err := s.inf.HashToken(ctx, tokenDomain)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	err = s.repo.RevokeSession(ctx, userId, refreshTokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("logout: %w", err))
	}

	return nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (domain.User, domain.Tokens, error) {
	tokenDomain, err := domain.NewToken(ctx, refreshToken, nil)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}

	refreshTokenHash, err := s.inf.HashToken(ctx, tokenDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}

	user, err := s.repo.ValidateSession(ctx, refreshTokenHash)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("validate refresh session: %w", err))
	}

	ctx = logger.WithLogID(ctx, user.ID())
	ctx = logger.WithLogName(ctx, user.Name())
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.inf.CreateJWT(ctx, user)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	tokens, err := domain.NewTokens(ctx, accessToken, tokenDomain)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}
	return user, tokens, nil
}
