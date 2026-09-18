package port

import (
	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/google/uuid"
)

//go:generate go run github.com/vektra/mockery/v2@v2.53.5 --name=TokenProvider
type TokenProvider interface {
	CreateRefreshToken() (domain.RefreshToken, error)
	CreateShortSessionToken() (domain.ShortSessionToken, error)
	CreateEmailVerificationToken() (domain.EmailVerificationToken, error)
	HashShortSessionToken(token domain.ShortSessionToken) (domain.ShortSessionTokenHash, error)
	HashRefreshToken(token domain.RefreshToken) (domain.RefreshTokenHash, error)
	HashEmailVerificationToken(token domain.EmailVerificationToken) (domain.EmailVerificationTokenHash, error)
	CreateJWT(user domain.User) (domain.AccessToken, error)
	CreateJWTWithSession(user domain.User, sessionID uuid.UUID) (domain.AccessToken, error)
}
