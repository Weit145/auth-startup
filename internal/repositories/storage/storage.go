package storage

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/google/uuid"
)

type Repositories interface {
	UserRepository
	SessionRepository
	CheckHealth(ctx context.Context) error
}

type UserRepository interface {
	CreateUserWithEmailVerificationToken(ctx context.Context, user domain.User, token domain.Token) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	VerifyEmailAndAddSession(ctx context.Context, userID uuid.UUID, emailToken, refreshToken domain.Token) (*domain.User, error)
}

type SessionRepository interface {
	AddSession(ctx context.Context, user domain.User, token domain.Token) (domain.User, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, token domain.Token) error
	ValidateSession(ctx context.Context, token domain.Token) (domain.User, error)
}
