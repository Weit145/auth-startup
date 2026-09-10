package port

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/google/uuid"
)

type Repository interface {
	RegisterRepository
	EventRepository
	UserRepository
	SessionRepository
	CheckHealth(ctx context.Context) error
}

type RegisterRepository interface {
	RegisterRequest(ctx context.Context, pendingUser domain.User, event event.Event, tokenHash domain.EmailVerificationTokenHash) error
	ConfirmEmail(ctx context.Context, userID uuid.UUID, shortSessionToken domain.ShortSessionTokenHash, tokenEmailHash domain.EmailVerificationTokenHash) (domain.User, uuid.UUID, error)
}

type UserRepository interface {
	// CreateEmailVerificationToken(ctx context.Context, email string, token domain.EmailVerificationTokenHash) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.Account, error)
	CompleteRegistration(ctx context.Context, sessionID uuid.UUID, passwordHash string, refreshToken domain.RefreshTokenHash) (domain.User, error)
	VerifyEmailAndAddShortSession(ctx context.Context, userID uuid.UUID, shortSessionToken domain.ShortSessionTokenHash, tokenEmailHash domain.EmailVerificationTokenHash) (domain.User, uuid.UUID, error)
	UpdateTokenEmail(ctx context.Context, email string, tokenHash domain.EmailVerificationTokenHash) (domain.User, error)
	PasswordRequest(ctx context.Context, email string, tokenHash domain.EmailVerificationTokenHash) (domain.User, error)
	PasswordConfirm(ctx context.Context, userID uuid.UUID, tokenHash domain.EmailVerificationTokenHash, passwordHash string) (domain.User, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPasswordHash string) (domain.User, error)
}

type SessionRepository interface {
	AddSession(ctx context.Context, user domain.User, token domain.RefreshTokenHash) (domain.User, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, token domain.RefreshTokenHash) error
	RotateSession(ctx context.Context, oldToken, newToken domain.RefreshTokenHash) (domain.User, error)
}

type EventRepository interface {
	// CreateEventOutbox(ctx context.Context, event event.Event) error
	SetEventError(ctx context.Context, eventID uuid.UUID) error
}
