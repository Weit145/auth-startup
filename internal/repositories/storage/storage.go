package storage

import (
	"context"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
)

type Repositories interface {
	CheckHealth(ctx context.Context) error
	CreateUser(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	AddSession(ctx context.Context, user domain.User, refreshTokenHash string, refreshTokenExpiresAt time.Time) (domain.User, error)
}
