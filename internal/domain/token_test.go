package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/google/uuid"
)

func TestRefreshToken(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidExpiresAt := time.Time{}
	cases := []struct {
		name      string
		value     string
		expiresAt *time.Time
		wantErr   error
	}{
		{
			name:      "valid token",
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   nil,
		},
		{
			name:      "invalid token",
			value:     "",
			expiresAt: &expiresAt,

			wantErr: errs.ErrInvalidInput,
		},
		{
			name:      "invalid expiresAt",
			value:     "valid-token",
			expiresAt: &invalidExpiresAt,

			wantErr: errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := domain.NewRefreshToken(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

			_, err = domain.NewRefreshTokenHash(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

		})
	}
}

func TestAccessToken(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidExpiresAt := time.Time{}
	cases := []struct {
		name      string
		value     string
		expiresAt *time.Time
		wantErr   error
	}{

		{
			name:      "valid token",
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   nil,
		},
		{
			name:      "invalid token",
			value:     "",
			expiresAt: &expiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
		{
			name:      "invalid expiresAt",
			value:     "valid-token",
			expiresAt: &invalidExpiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := domain.NewAccessToken(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

		})
	}
}

func TestEmailVerificationToken(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidExpiresAt := time.Time{}
	cases := []struct {
		name      string
		value     string
		expiresAt *time.Time
		wantErr   error
	}{

		{
			name:      "valid token",
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   nil,
		},
		{
			name:      "invalid token",
			value:     "",
			expiresAt: &expiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
		{
			name:      "invalid expiresAt",
			value:     "valid-token",
			expiresAt: &invalidExpiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := domain.NewEmailVerificationToken(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}
			_, err = domain.NewRefreshTokenHash(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

		})
	}
}

func TestShortSessionToken(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidExpiresAt := time.Time{}
	cases := []struct {
		name      string
		value     string
		expiresAt *time.Time
		wantErr   error
	}{

		{
			name:      "valid token",
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   nil,
		},
		{
			name:      "invalid token",
			value:     "",
			expiresAt: &expiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
		{
			name:      "invalid expiresAt",
			value:     "valid-token",
			expiresAt: &invalidExpiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			_, err := domain.NewShortSessionToken(
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

		})
	}
}

func TestShortSessionTokenHash(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	invalidExpiresAt := time.Time{}
	sessionID := uuid.New()
	cases := []struct {
		name      string
		sessionID uuid.UUID
		value     string
		expiresAt *time.Time
		wantErr   error
	}{

		{
			name:      "valid token",
			sessionID: sessionID,
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   nil,
		},
		{
			name:      "invalid token",
			sessionID: sessionID,
			value:     "",
			expiresAt: &expiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
		{
			name:      "invalid expiresAt",
			sessionID: sessionID,
			value:     "valid-token",
			expiresAt: &invalidExpiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
		{
			name:      "empty sessionID",
			sessionID: uuid.Nil,
			value:     "valid-token",
			expiresAt: &expiresAt,
			wantErr:   errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc

			_, err := domain.NewShortSessionTokenHash(
				tc.sessionID,
				tc.value,
				tc.expiresAt,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh hash: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

		})
	}
}

func TestNewTokens(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	access, err := domain.NewAccessToken(
		"value",
		&expiresAt,
	)
	if err != nil {
		t.Fatalf("error creating access token: %v", err)
	}
	refresh, err := domain.NewRefreshToken(
		"value",
		&expiresAt,
	)
	if err != nil {
		t.Fatalf("error creating refresh token: %v", err)
	}
	cases := []struct {
		name    string
		refresh domain.RefreshToken
		access  domain.AccessToken
		wantErr error
	}{

		{
			name:    "valid token",
			refresh: refresh,
			access:  access,
			wantErr: nil,
		},
		{
			name:    "invalid access token",
			refresh: refresh,
			access:  domain.AccessToken{},
			wantErr: errs.ErrInvalidInput,
		},
		{
			name:    "invalid access token",
			refresh: domain.RefreshToken{},
			access:  access,
			wantErr: errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc

			tokens, err := domain.NewTokens(
				tc.access,
				tc.refresh,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error token refresh hash: %v, wait %v",
					err,
					tc.wantErr,
				)
			}

			if tc.access.Value() != tokens.AccessToken().Value() {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("access token value mismatch: got %s, want %s",
						tokens.AccessToken().Value(),
						tc.access.Value(),
					)
				}
			}
			if tc.refresh.Value() != tokens.RefreshToken().Value() {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("refresh token value mismatch: got %s, want %s",
						tokens.RefreshToken().Value(),
						tc.refresh.Value(),
					)
				}
			}

		})
	}
}
