package port

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/google/uuid"
)

//go:generate go run github.com/vektra/mockery/v2@v2.53.5 --name=Repository
type Repository interface {
	RegisterRepository
	LoginRepository
	PasswordRepository
	RefreshSessionRepository
	EventRepository
	CheckHealth(ctx context.Context) error
}

type RegisterRepository interface {
	RegisterRequest(
		ctx context.Context,
		pendingUser domain.User,
		event event.Event,
		tokenHash domain.EmailVerificationTokenHash,
	) error
	ConfirmEmail(
		ctx context.Context,
		userID uuid.UUID,
		shortSessionToken domain.ShortSessionTokenHash,
		tokenEmailHash domain.EmailVerificationTokenHash,
	) (domain.User, uuid.UUID, error)
	RegisterComplete(
		ctx context.Context,
		sessionID uuid.UUID,
		passwordHash string,
		refreshToken domain.RefreshTokenHash,
	) (domain.User, error)

	RepeatEmail(
		ctx context.Context,
		email string,
		event event.Event,
		tokenEmailHash domain.EmailVerificationTokenHash,
	) error
}

type LoginRepository interface {
	GetAccountByEmail(
		ctx context.Context,
		email string,
	) (domain.Account, error)
	AddSession(
		ctx context.Context,
		user domain.User,
		token domain.RefreshTokenHash,
	) (domain.User, error)
	RevokeSession(
		ctx context.Context,
		userID uuid.UUID,
		token domain.RefreshTokenHash,
	) error
}

type PasswordRepository interface {
	PasswordRequest(
		ctx context.Context,
		email string,
		tokenHash domain.EmailVerificationTokenHash,
		event event.Event,
	) error
	PasswordConfirm(
		ctx context.Context,
		userID uuid.UUID,
		tokenHash domain.EmailVerificationTokenHash,
		passwordHash string,
	) (domain.User, error)
	ChangePassword(
		ctx context.Context,
		userID uuid.UUID,
		oldPassword, newPasswordHash string,
	) (domain.User, error)
}

type RefreshSessionRepository interface {
	RotateSession(
		ctx context.Context,
		oldToken domain.RefreshTokenHash,
		newToken domain.RefreshTokenHash,
	) (domain.User, error)
}

type EventRepository interface {
	SetEventError(ctx context.Context, eventID uuid.UUID) error
}
