package port

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain"
)

type TokenProvider interface {
	CreateJWT(ctx context.Context, user domain.User) (domain.Token, error)
	CreateToken(ctx context.Context) (domain.Token, error)
	HashToken(ctx context.Context, token domain.Token) (domain.Token, error)
}
