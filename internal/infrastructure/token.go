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
	CreateJWT(ctx context.Context, user domain.User) (domain.Token, error)
	CreateToken(ctx context.Context) (domain.Token, error)
	HashToken(ctx context.Context, token domain.Token) (domain.Token, error)
}

type AccessClaims struct {
	Role string `json:"role"`
	Type string `json:"typ"`

	jwt.RegisteredClaims
}

func (i *Infrastructure) CreateToken(ctx context.Context) (domain.Token, error) {
	b := make([]byte, 64)

	if _, err := rand.Read(b); err != nil {
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("create token: %w", err))
	}
	hashToken := base64.RawURLEncoding.EncodeToString(b)

	token, err := domain.NewToken(ctx, hashToken, nil)
	if err != nil {
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("create domain token: %w", err))
	}

	return token, nil
}

func (i *Infrastructure) HashToken(ctx context.Context, token domain.Token) (domain.Token, error) {
	h := hmac.New(sha256.New, []byte(i.cfg.JWT.RefreshSecret))
	h.Write([]byte(token.Value()))

	hash := hex.EncodeToString(h.Sum(nil))
	var expiresAt *time.Time
	if value, ok := token.ExpiresAt(); ok {
		expiresAt = &value
	}

	tokenHash, err := domain.NewToken(ctx, hash, expiresAt)
	if err != nil {
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("create domain token: %w", err))
	}

	return tokenHash, nil
}

func (i *Infrastructure) CreateJWT(ctx context.Context, user domain.User) (domain.Token, error) {
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
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("JWT private key is not configured"))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(i.cfg.JWT.PrivateKey)
	if err != nil {
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("failed to sign JWT: %w", err))
	}

	tokenDomain, err := domain.NewToken(ctx, tokenString, &claims.ExpiresAt.Time)
	if err != nil {
		return domain.Token{}, logger.WrapError(ctx, fmt.Errorf("create domain token: %w", err))
	}
	return tokenDomain, nil
}
