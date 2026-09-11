package usecase

import (
	"context"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
)

func (s *Service) RegisterRequest(ctx context.Context, email string) error {
	token, err := s.tokens.CreateEmailVerificationToken()
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err))
	}
	token.CreateExpiresAt(s.cfg.EmailVerificationTokenTTL)
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tokenHash, err := s.tokens.HashEmailVerificationToken(token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash token for email verification: %w", err))
	}

	pendingUser, err := domain.NewUser(uuid.New(), email, "user")
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create pending user: %w", err))
	}
	userID := pendingUser.ID()
	event, err := event.NewEvent(pendingUser.Email(), s.cfg.EmailVerificationURL, token, tokenExpiresAt, &userID, event.EmailVerificationRequestedType)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
	}

	err = s.repo.RegisterRequest(ctx, *pendingUser, event, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("RegisterRequest repo: %w", err))
	}
	return nil
}

func (s *Service) ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.AccessToken, error) {
	tokenEmailDomain, err := domain.NewEmailVerificationToken(token, nil)
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("create token domain: %w", err))
	}
	tokenEmailHash, err := s.tokens.HashEmailVerificationToken(tokenEmailDomain)
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("hash email verification token: %w", err))
	}
	shortSessionToken, err := s.tokens.CreateShortSessionToken()
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("create short session token: %w", err))
	}
	shortSessionToken.CreateExpiresAt(s.cfg.ShortSessionTTL)
	shortSessionTokenHash, err := s.tokens.HashShortSessionToken(shortSessionToken)
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("hash short session token: %w", err))
	}
	user, sessionID, err := s.repo.VerifyEmailAndAddShortSession(
		ctx,
		userID,
		shortSessionTokenHash,
		tokenEmailHash,
	)
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("verify email and add session: %w", err))
	}

	ctx = logger.WithLogSessionID(ctx, sessionID)
	ctx = logger.WithLogID(ctx, userID)
	ctx = logger.WithLogEmail(ctx, user.Email())

	accessToken, err := s.tokens.CreateJWTWithSession(user, sessionID)
	if err != nil {
		return domain.AccessToken{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}

	return accessToken, nil
}

func (s *Service) RegisterComplete(ctx context.Context, sessionID uuid.UUID, password string) (domain.User, domain.Tokens, error) {
	passwordHash, err := domain.HashPassword(password)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash password: %w", err))
	}

	refreshToken, err := s.tokens.CreateRefreshToken()
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create refresh token: %w", err))
	}
	refreshToken.CreateExpiresAt(s.cfg.RefreshTokenTTL)
	refreshTokenHash, err := s.tokens.HashRefreshToken(refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("hash refresh token: %w", err))
	}
	domainUser, err := s.repo.RegisterComplete(
		ctx,
		sessionID,
		passwordHash,
		refreshTokenHash,
	)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("complete registration: %w", err))
	}

	ctx = logger.WithLogID(ctx, domainUser.ID())
	ctx = logger.WithLogEmail(ctx, domainUser.Email())

	accessToken, err := s.tokens.CreateJWT(domainUser)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create access token: %w", err))
	}
	tokens, err := domain.NewTokens(accessToken, refreshToken)
	if err != nil {
		return domain.User{}, domain.Tokens{}, logger.WrapError(ctx, fmt.Errorf("create tokens: %w", err))
	}

	return domainUser, tokens, nil
}

func (s *Service) RepeatEmail(ctx context.Context, email string) error {
	token, err := s.tokens.CreateEmailVerificationToken()
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create token for email verification: %w", err))
	}
	token.CreateExpiresAt(s.cfg.EmailVerificationTokenTTL)
	tokenExpiresAt, ok := token.ExpiresAt()
	if !ok {
		return logger.WrapError(ctx, fmt.Errorf("email verification token expiration is not set"))
	}

	tokenHash, err := s.tokens.HashEmailVerificationToken(token)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("hash token for email verification: %w", err))
	}
	event, err := event.NewEvent(email, s.cfg.EmailVerificationURL, token, tokenExpiresAt, nil, event.ReapitEmailVerificationType)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
	}

	err = s.repo.RepeatEmail(ctx, email, event, tokenHash)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("repeat email: %w", err))
	}

	// err = s.notifications.AddEvent(ctx, event)
	// if err != nil {
	// 	err = s.repo.SetEventError(ctx, event.EventID())
	// 	if err != nil {
	// 		return logger.WrapError(ctx, fmt.Errorf("set event error: %w", err))
	// 	}
	// 	return logger.WrapError(ctx, fmt.Errorf("publish email: %w", err))
	// }

	return nil
}
