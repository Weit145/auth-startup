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
	CreateHashToken(ctx context.Context) (string, error)
	HashToken(token string) string
	HashRefreshToken(refreshToken string) string
}

type AccessClaims struct {
	Role string `json:"role"`
	Type string `json:"typ"`

	jwt.RegisteredClaims
}

func (i *Infrastructure) CreateHashToken(ctx context.Context) (string, error) {
	b := make([]byte, 64)

	if _, err := rand.Read(b); err != nil {
		return "", logger.WrapError(ctx, fmt.Errorf("create hash token"))
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (i *Infrastructure) HashToken(token string) string {
	h := hmac.New(sha256.New, []byte(i.cfg.JWT.RefreshSecret))
	h.Write([]byte(token))

	return hex.EncodeToString(h.Sum(nil))
}

func (i *Infrastructure) HashRefreshToken(refreshToken string) string {
	return i.HashToken(refreshToken)
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
			ExpiresAt: jwt.NewNumericDate(now.Add(i.cfg.Time.AccessTokenTTL)),
			ID:        uuid.NewString(),
		},
	}

	if i.cfg.JWT.PrivateKey == nil {
		return "", logger.WrapError(ctx, fmt.Errorf("JWT private key is not configured"))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(i.cfg.JWT.PrivateKey)
	if err != nil {
		return "", logger.WrapError(ctx, fmt.Errorf("failed to sign JWT: %w", err))
	}
	return tokenString, nil
}
