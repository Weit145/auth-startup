package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
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
