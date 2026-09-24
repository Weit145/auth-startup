package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/infrastructure/token"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestCreateRefreshToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	provider := token.NewProvider(cfg)
	refreshToken, err := provider.CreateRefreshToken()
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if refreshToken.Value() == "" {
		t.Fatal("created refresh token is empty")
	}
}

func TestCreateShortSessionToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	provider := token.NewProvider(cfg)
	shortSessionToken, err := provider.CreateShortSessionToken()
	if err != nil {
		t.Fatalf("create short session token: %v", err)
	}
	if shortSessionToken.Value() == "" {
		t.Fatal("created short session token is empty")
	}
}

func TestCreateEmailVerificationToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	provider := token.NewProvider(cfg)
	emailVerificationToken, err := provider.CreateEmailVerificationToken()
	if err != nil {
		t.Fatalf("create email verification token: %v", err)
	}
	if emailVerificationToken.Value() == "" {
		t.Fatal("created email verification token is empty")
	}
}

func TestHashRefreshToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	cases := []struct {
		name         string
		refreshToken string
		expected     time.Time
		waitErr      error
	}{
		{
			name:         "valid",
			refreshToken: "token",
			expected:     time.Now().Add(time.Hour),
		},
		{
			name:         "invalid expired",
			refreshToken: "token",
			expected:     time.Now().Add(-time.Hour),
			waitErr:      errs.ErrInvalidInput,
		},
		{
			name:     "empty token",
			expected: time.Now().Add(time.Hour),
			waitErr:  errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tokenR, err := domain.NewRefreshToken(tc.refreshToken, &tc.expected)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
				return
			}

			provider := token.NewProvider(cfg)

			resultToken, err := provider.HashRefreshToken(tokenR)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if err != nil {
				return
			}
			if resultToken.Value() == tokenR.Value() {
				t.Fatalf("resultToken value %v, got %v", resultToken.Value(), tokenR.Value())
			}
		})
	}
}

func TestHashShortSessionToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	cases := []struct {
		name     string
		token    string
		expected time.Time
		waitErr  error
	}{
		{
			name:     "valid",
			token:    "token",
			expected: time.Now().Add(time.Hour),
		},
		{
			name:     "invalid expired",
			token:    "token",
			expected: time.Now().Add(-time.Hour),
			waitErr:  errs.ErrInvalidInput,
		},
		{
			name:     "empty token",
			expected: time.Now().Add(time.Hour),
			waitErr:  errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessionToken, err := domain.NewShortSessionToken(tc.token, &tc.expected)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
				return
			}

			provider := token.NewProvider(cfg)

			resultToken, err := provider.HashShortSessionToken(sessionToken)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if err != nil {
				return
			}
			if resultToken.Value() == sessionToken.Value() {
				t.Fatalf("resultToken value %v, got %v", resultToken.Value(), sessionToken.Value())
			}
		})
	}
}

func TestHashEmailVerificationToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	cfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}

	cases := []struct {
		name     string
		token    string
		expected time.Time
		waitErr  error
	}{
		{
			name:     "valid",
			token:    "token",
			expected: time.Now().Add(time.Hour),
		},
		{
			name:     "invalid expired",
			token:    "token",
			expected: time.Now().Add(-time.Hour),
			waitErr:  errs.ErrInvalidInput,
		},
		{
			name:     "empty token",
			expected: time.Now().Add(time.Hour),
			waitErr:  errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			emailVerToken, err := domain.NewEmailVerificationToken(tc.token, &tc.expected)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
				return
			}

			provider := token.NewProvider(cfg)

			resultToken, err := provider.HashEmailVerificationToken(emailVerToken)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if err != nil {
				return
			}
			if resultToken.Value() == emailVerToken.Value() {
				t.Fatalf("resultToken value %v, got %v", resultToken.Value(), emailVerToken.Value())
			}
		})
	}
}

func parseAccessClaims(
	t *testing.T,
	value string,
	publicKey *rsa.PublicKey,
) *token.AccessClaims {
	t.Helper()

	claims := &token.AccessClaims{}
	parsedToken, err := jwt.ParseWithClaims(
		value,
		claims,
		func(jwtToken *jwt.Token) (any, error) {
			if jwtToken.Method != jwt.SigningMethodRS256 {
				t.Fatalf("unexpected signing method: %v", jwtToken.Header["alg"])
			}
			return publicKey, nil
		},
	)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatal("access token is invalid")
	}

	return claims
}

func TestCreateJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	user, err := domain.NewUser(uuid.New(), "test@example.com", "user")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	validCfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}
	withoutPrivateKeyCfg := validCfg
	withoutPrivateKeyCfg.PrivateKey = nil
	invalidTTLCfg := validCfg
	invalidTTLCfg.AccessTokenTTL = 0

	cases := []struct {
		name    string
		cfg     token.Settings
		wantErr bool
		waitErr error
	}{
		{
			name: "valid",
			cfg:  validCfg,
		},
		{
			name:    "private key is not configured",
			cfg:     withoutPrivateKeyCfg,
			wantErr: true,
		},
		{
			name:    "invalid access token TTL",
			cfg:     invalidTTLCfg,
			wantErr: true,
			waitErr: errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := token.NewProvider(tc.cfg)
			result, err := provider.CreateJWT(*user)
			if tc.waitErr != nil && !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("expected error: %v, got %v", tc.wantErr, err)
			}
			if err != nil {
				return
			}
			if result.Value() == "" {
				t.Fatal("created access token is empty")
			}

			claims := parseAccessClaims(t, result.Value(), &privateKey.PublicKey)
			if claims.Subject != user.ID().String() {
				t.Fatalf("expected subject %q, got %q", user.ID(), claims.Subject)
			}
			if claims.Role != user.Role() {
				t.Fatalf("expected role %q, got %q", user.Role(), claims.Role)
			}
			if claims.Type != "access" {
				t.Fatalf("expected type %q, got %q", "access", claims.Type)
			}
			if claims.Issuer != "auth-service" {
				t.Fatalf("expected issuer %q, got %q", "auth-service", claims.Issuer)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != "gateway" {
				t.Fatalf("expected audience %q, got %v", "gateway", claims.Audience)
			}
			if claims.ID == "" {
				t.Fatal("JWT ID is empty")
			}
			if claims.IssuedAt == nil || claims.ExpiresAt == nil {
				t.Fatal("JWT timestamps are not set")
			}
			if claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) != tc.cfg.AccessTokenTTL {
				t.Fatalf(
					"expected access token TTL %v, got %v",
					tc.cfg.AccessTokenTTL,
					claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time),
				)
			}
		})
	}
}

func TestCreateJWTWithSession(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA private key: %v", err)
	}

	user, err := domain.NewUser(uuid.New(), "test@example.com", "user")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	validCfg := token.Settings{
		PrivateKey:      privateKey,
		RefreshSecret:   "test-refresh-secret",
		AccessTokenTTL:  15 * time.Minute,
		ShortSessionTTL: 5 * time.Minute,
	}
	withoutPrivateKeyCfg := validCfg
	withoutPrivateKeyCfg.PrivateKey = nil
	invalidTTLCfg := validCfg
	invalidTTLCfg.ShortSessionTTL = 0
	sessionID := uuid.New()

	cases := []struct {
		name      string
		cfg       token.Settings
		sessionID uuid.UUID
		wantErr   bool
		waitErr   error
	}{
		{
			name:      "valid",
			cfg:       validCfg,
			sessionID: sessionID,
		},
		{
			name:      "empty session ID",
			cfg:       validCfg,
			sessionID: uuid.Nil,
			wantErr:   true,
		},
		{
			name:      "private key is not configured",
			cfg:       withoutPrivateKeyCfg,
			sessionID: sessionID,
			wantErr:   true,
		},
		{
			name:      "invalid short session TTL",
			cfg:       invalidTTLCfg,
			sessionID: sessionID,
			wantErr:   true,
			waitErr:   errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := token.NewProvider(tc.cfg)
			result, err := provider.CreateJWTWithSession(*user, tc.sessionID)
			if tc.waitErr != nil && !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("expected error: %v, got %v", tc.wantErr, err)
			}
			if err != nil {
				return
			}
			if result.Value() == "" {
				t.Fatal("created access token is empty")
			}

			claims := parseAccessClaims(t, result.Value(), &privateKey.PublicKey)
			if claims.Subject != tc.sessionID.String() {
				t.Fatalf("expected subject %q, got %q", tc.sessionID, claims.Subject)
			}
			if claims.ID != user.ID().String() {
				t.Fatalf("expected JWT ID %q, got %q", user.ID(), claims.ID)
			}
			if claims.Role != user.Role() {
				t.Fatalf("expected role %q, got %q", user.Role(), claims.Role)
			}
			if claims.Type != "access" {
				t.Fatalf("expected type %q, got %q", "access", claims.Type)
			}
			if claims.Issuer != "auth-service" {
				t.Fatalf("expected issuer %q, got %q", "auth-service", claims.Issuer)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != "gateway" {
				t.Fatalf("expected audience %q, got %v", "gateway", claims.Audience)
			}
			if claims.IssuedAt == nil || claims.ExpiresAt == nil {
				t.Fatal("JWT timestamps are not set")
			}
			if claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) != tc.cfg.ShortSessionTTL {
				t.Fatalf(
					"expected short session TTL %v, got %v",
					tc.cfg.ShortSessionTTL,
					claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time),
				)
			}
		})
	}
}
