package port

import (
	"github.com/Weit145/auth-startup/internal/domain"
)

type TokenProvider interface {
	CreateRefreshToken() (domain.RefreshToken, error)
	CreateEmailVerificationToken() (domain.EmailVerificationToken, error)
	HashRefreshToken(token domain.RefreshToken) (domain.RefreshTokenHash, error)
	HashEmailVerificationToken(token domain.EmailVerificationToken) (domain.EmailVerificationTokenHash, error)
	CreateJWT(user domain.User) (domain.AccessToken, error)
}
