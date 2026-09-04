package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessClaims struct {
	Role string `json:"role"`
	Type string `json:"typ"`

	jwt.RegisteredClaims
}

func (p *Provider) CreateRefreshToken() (domain.RefreshToken, error) {
	b := make([]byte, 64)

	if _, err := rand.Read(b); err != nil {
		return domain.RefreshToken{}, fmt.Errorf("create token: %w", err)
	}
	hashToken := base64.RawURLEncoding.EncodeToString(b)

	token, err := domain.NewRefreshToken(hashToken, nil)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("create domain token: %w", err)
	}

	return token, nil
}

func (p *Provider) CreateShortSessionToken() (domain.ShortSessionToken, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return domain.ShortSessionToken{}, fmt.Errorf("create short session token: %w", err)
	}

	value := base64.RawURLEncoding.EncodeToString(b)
	token, err := domain.NewShortSessionToken(value, nil)
	if err != nil {
		return domain.ShortSessionToken{}, fmt.Errorf("create short session domain token: %w", err)
	}

	return token, nil
}

func (p *Provider) CreateEmailVerificationToken() (domain.EmailVerificationToken, error) {
	b := make([]byte, 64)

	if _, err := rand.Read(b); err != nil {
		return domain.EmailVerificationToken{}, fmt.Errorf("create token: %w", err)
	}
	hashToken := base64.RawURLEncoding.EncodeToString(b)

	token, err := domain.NewEmailVerificationToken(hashToken, nil)
	if err != nil {
		return domain.EmailVerificationToken{}, fmt.Errorf("create domain token: %w", err)
	}

	return token, nil
}

func (p *Provider) HashRefreshToken(token domain.RefreshToken) (domain.RefreshTokenHash, error) {
	h := hmac.New(sha256.New, []byte(p.cfg.RefreshSecret))
	h.Write([]byte(token.Value()))

	hash := hex.EncodeToString(h.Sum(nil))
	var expiresAt *time.Time
	if value, ok := token.ExpiresAt(); ok {
		expiresAt = &value
	}

	tokenHash, err := domain.NewRefreshTokenHash(hash, expiresAt)
	if err != nil {
		return domain.RefreshTokenHash{}, fmt.Errorf("create domain token: %w", err)
	}

	return tokenHash, nil
}

func (p *Provider) HashShortSessionToken(token domain.ShortSessionToken) (domain.ShortSessionTokenHash, error) {
	h := hmac.New(sha256.New, []byte(p.cfg.RefreshSecret))
	h.Write([]byte(token.Value()))

	hash := hex.EncodeToString(h.Sum(nil))
	var expiresAt *time.Time
	if value, ok := token.ExpiresAt(); ok {
		expiresAt = &value
	}

	tokenHash, err := domain.NewShortSessionTokenHash(token.ID(), hash, expiresAt)
	if err != nil {
		return domain.ShortSessionTokenHash{}, fmt.Errorf("create short session token hash: %w", err)
	}

	return tokenHash, nil
}

func (p *Provider) HashEmailVerificationToken(token domain.EmailVerificationToken) (domain.EmailVerificationTokenHash, error) {
	h := hmac.New(sha256.New, []byte(p.cfg.RefreshSecret))
	h.Write([]byte(token.Value()))

	hash := hex.EncodeToString(h.Sum(nil))
	var expiresAt *time.Time
	if value, ok := token.ExpiresAt(); ok {
		expiresAt = &value
	}

	tokenHash, err := domain.NewEmailVerificationTokenHash(hash, expiresAt)
	if err != nil {
		return domain.EmailVerificationTokenHash{}, fmt.Errorf("create domain token: %w", err)
	}

	return tokenHash, nil
}

func (p *Provider) CreateJWT(user domain.User) (domain.AccessToken, error) {
	now := time.Now()

	claims := AccessClaims{
		Role: user.Role(),
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID().String(),
			Issuer:    "auth-service",
			Audience:  []string{"gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.cfg.AccessTokenTTL)),
			ID:        uuid.NewString(),
		},
	}

	if p.cfg.PrivateKey == nil {
		return domain.AccessToken{}, fmt.Errorf("JWT private key is not configured")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(p.cfg.PrivateKey)
	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("failed to sign JWT: %w", err)
	}

	tokenDomain, err := domain.NewAccessToken(tokenString, &claims.ExpiresAt.Time)
	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("create domain token: %w", err)
	}
	return tokenDomain, nil
}

func (p *Provider) CreateJWTWithSession(user domain.User, sessionID uuid.UUID) (domain.AccessToken, error) {
	if sessionID == uuid.Nil {
		return domain.AccessToken{}, fmt.Errorf("registration session id is empty")
	}

	now := time.Now()
	claims := AccessClaims{
		Role: user.Role(),
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sessionID.String(),
			Issuer:    "auth-service",
			Audience:  []string{"gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.cfg.ShortSessionTTL)),
			ID:        user.ID().String(),
		},
	}

	if p.cfg.PrivateKey == nil {
		return domain.AccessToken{}, fmt.Errorf("JWT private key is not configured")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(p.cfg.PrivateKey)
	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("sign registration JWT: %w", err)
	}

	tokenDomain, err := domain.NewAccessToken(tokenString, &claims.ExpiresAt.Time)
	if err != nil {
		return domain.AccessToken{}, fmt.Errorf("create registration access token: %w", err)
	}

	return tokenDomain, nil
}
