package infrastructure

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Token interface {
	CreateJWT(ctx context.Context, user domain.User) (string, error)
	CreateRefreshToken() (string, error)
	HashRefreshToken(refreshToken string) string
}

type AccessClaims struct {
	Role string `json:"role"`
	Type string `json:"typ"`

	jwt.RegisteredClaims
}

func (i *Infrastructure) CreateRefreshToken() (string, error) {
	const op = "token.CreateRefreshToken"

	b := make([]byte, 64)

	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (i *Infrastructure) HashRefreshToken(refreshToken string) string {
	h := hmac.New(sha256.New, []byte(i.cfg.JWT.RefreshSecret))
	h.Write([]byte(refreshToken))

	return hex.EncodeToString(h.Sum(nil))
}

func (i *Infrastructure) CreateJWT(ctx context.Context, user domain.User) (string, error) {
	now := time.Now()

	claims := AccessClaims{
		Role: user.Role(),
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID().String(),
			Issuer:    "auth-service",
			Audience:  []string{"gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(i.cfg.JWT.Secret))
	if err != nil {
		return "", logger.WrapError(ctx, fmt.Errorf("failed to sign JWT: %w", err))
	}
	return tokenString, nil
}
