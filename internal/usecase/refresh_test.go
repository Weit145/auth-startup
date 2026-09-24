package usecase_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/usecase"
	"github.com/Weit145/auth-startup/internal/usecase/port/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func TestRefreshToken(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	expiresAt := time.Now().Add(time.Hour)

	refreshToken, err := domain.NewRefreshToken("token", &expiresAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	refreshTokenHash, err := domain.NewRefreshTokenHash(refreshToken.Value(), &expiresAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	user, err := domain.NewUser(uuid.New(), "test@example.com", "user")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	accessToken, err := domain.NewAccessToken("token", &expiresAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	type expectedCalls struct {
		hashRefresh       bool
		createRefresh     bool
		hashNewRefresh    bool
		repo              bool
		createAccessToken bool
	}

	cases := []struct {
		name                   string
		refreshToken           string
		hashRefreshTokenErr    error
		createRefreshTokenErr  error
		hashNewRefreshTokenErr error
		repoErr                error
		createAccessTokenErr   error
		waitErr                error
		calls                  expectedCalls
	}{
		{
			name:         "valid",
			refreshToken: "token",
			calls: expectedCalls{
				hashRefresh:       true,
				createRefresh:     true,
				hashNewRefresh:    true,
				repo:              true,
				createAccessToken: true,
			},
		},
		{
			name:         "empty refresh token",
			refreshToken: "",
			waitErr:      errs.ErrInvalidInput,
		},
		{
			name:                "error hash old refresh token",
			refreshToken:        "token",
			hashRefreshTokenErr: errs.ErrInternal,
			waitErr:             errs.ErrInternal,
			calls: expectedCalls{
				hashRefresh: true,
			},
		},
		{
			name:                  "error create new refresh token",
			refreshToken:          "token",
			createRefreshTokenErr: errs.ErrInternal,
			waitErr:               errs.ErrInternal,
			calls: expectedCalls{
				hashRefresh:   true,
				createRefresh: true,
			},
		},
		{
			name:                   "error hash new refresh token",
			refreshToken:           "token",
			hashNewRefreshTokenErr: errs.ErrInternal,
			waitErr:                errs.ErrInternal,
			calls: expectedCalls{
				hashRefresh:    true,
				createRefresh:  true,
				hashNewRefresh: true,
			},
		},
		{
			name:         "error repo",
			refreshToken: "token",
			repoErr:      errs.ErrInternal,
			waitErr:      errs.ErrInternal,
			calls: expectedCalls{
				hashRefresh:    true,
				createRefresh:  true,
				hashNewRefresh: true,
				repo:           true,
			},
		},
		{
			name:                 "error create access token",
			refreshToken:         "token",
			createAccessTokenErr: errs.ErrInternal,
			waitErr:              errs.ErrInternal,
			calls: expectedCalls{
				hashRefresh:       true,
				createRefresh:     true,
				hashNewRefresh:    true,
				repo:              true,
				createAccessToken: true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			if tc.calls.hashRefresh {
				tokens.On("HashRefreshToken", mock.Anything).
					Return(refreshTokenHash, tc.hashRefreshTokenErr).
					Once()
			}
			if tc.calls.createRefresh {
				tokens.On("CreateRefreshToken").
					Return(refreshToken, tc.createRefreshTokenErr).
					Once()
			}

			if tc.calls.hashNewRefresh {
				tokens.On("HashRefreshToken", mock.Anything).
					Return(refreshTokenHash, tc.hashNewRefreshTokenErr).
					Once()
			}
			if tc.calls.repo {
				repo.On("RotateSession", mock.Anything, mock.Anything, refreshTokenHash).
					Return(*user, tc.repoErr).
					Once()
			}
			if tc.calls.createAccessToken {
				tokens.On("CreateJWT", *user).
					Return(accessToken, tc.createAccessTokenErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			userResult, tokensResult, err := service.RefreshToken(context.Background(), tc.refreshToken)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if err == nil && userResult != *user {
				t.Fatalf("expected user %v, got %v", *user, userResult)
			}

			if err == nil && tokensResult.AccessToken() != accessToken {
				t.Fatalf(
					"expected access token %q, got %q",
					accessToken.Value(),
					tokensResult.AccessToken().Value(),
				)
			}

			if err == nil && tokensResult.RefreshToken().Value() != refreshToken.Value() {
				t.Fatalf(
					"expected refresh token %q, got %q",
					refreshToken.Value(),
					tokensResult.RefreshToken().Value(),
				)
			}
		})
	}
}
