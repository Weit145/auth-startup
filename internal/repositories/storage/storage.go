package storage

import (
	"context"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/google/uuid"
)

type Repositories interface {
	CheckHealth(ctx context.Context) error
	CreateUserWithEmailVerificationToken(ctx context.Context, user domain.User, tokenHash string, expiresAt time.Time) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	VerifyEmail(ctx context.Context, userID uuid.UUID, tokenHash string) (*domain.User, error)
	AddSession(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error)
}
