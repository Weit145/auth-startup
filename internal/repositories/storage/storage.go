package storage

import (
	"context"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/google/uuid"
)

type Repositories interface {
	UserRepository
	SessionRepository
	CheckHealth(ctx context.Context) error
}

type UserRepository interface {
	CreateUserWithEmailVerificationToken(ctx context.Context, user domain.User, tokenHash string, expiresAt time.Time) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	VerifyEmailAndAddSession(ctx context.Context, userID uuid.UUID, tokenHash string, refreshTokenHash string, refreshTokenExpiresAt time.Time) (*domain.User, error)
}

type SessionRepository interface {
	AddSession(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, refreshTokenHash string) error
	ValidateSession(ctx context.Context, refreshTokenHash string) (domain.User, error)
}
