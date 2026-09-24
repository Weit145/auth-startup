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

func TestLogin(t *testing.T) {

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

	account, err := domain.NewUserAccount("test@example.com", "123456")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	accessToken, err := domain.NewAccessToken("token", &expiresAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	type expectedCalls struct {
		repoGet            bool
		createRefreshToken bool
		hashRefreshToken   bool
		createAccessToken  bool
		repoAdd            bool
	}

	cases := []struct {
		name                  string
		email                 string
		password              string
		repoGetErr            error
		createRefreshTokenErr error
		hashRefreshTokenErr   error
		createAccessTokenErr  error
		repoAddErr            error
		wantErr               error
		calls                 expectedCalls
	}{
		{
			name:     "valid",
			email:    "test@example.com",
			password: "123456",
			calls: expectedCalls{
				repoGet:            true,
				createRefreshToken: true,
				hashRefreshToken:   true,
				createAccessToken:  true,
				repoAdd:            true,
			},
		},
		{
			name:       "invalid email",
			email:      "test",
			password:   "123456",
			repoGetErr: errs.ErrInvalidInput,
			wantErr:    errs.ErrInvalidInput,
			calls:      expectedCalls{repoGet: true},
		},
		{
			name:       "empty email",
			email:      "",
			password:   "123456",
			repoGetErr: errs.ErrInvalidInput,
			wantErr:    errs.ErrInvalidInput,
			calls:      expectedCalls{repoGet: true},
		},
		{
			name:       "not found",
			email:      "test@example.com",
			password:   "123456",
			repoGetErr: errs.ErrNotFound,
			wantErr:    errs.ErrUnauthorized,
			calls:      expectedCalls{repoGet: true},
		},
		{
			name:     "invalid password",
			email:    "test@example.com",
			password: "123",
			wantErr:  errs.ErrUnauthorized,
			calls:    expectedCalls{repoGet: true},
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
			wantErr:  errs.ErrUnauthorized,
			calls:    expectedCalls{repoGet: true},
		},
		{
			name:       "err repoGet",
			email:      "test@example.com",
			password:   "123456",
			repoGetErr: errs.ErrInternal,
			wantErr:    errs.ErrInternal,
			calls:      expectedCalls{repoGet: true},
		},
		{
			name:                  "err createRefreshToken",
			email:                 "test@example.com",
			password:              "123456",
			createRefreshTokenErr: errs.ErrInternal,
			wantErr:               errs.ErrInternal,
			calls: expectedCalls{
				repoGet:            true,
				createRefreshToken: true,
			},
		},
		{
			name:                "err hashRefreshToken",
			email:               "test@example.com",
			password:            "123456",
			hashRefreshTokenErr: errs.ErrInternal,
			wantErr:             errs.ErrInternal,
			calls: expectedCalls{
				repoGet:            true,
				createRefreshToken: true,
				hashRefreshToken:   true,
			},
		},
		{
			name:                 "err createAccessToken",
			email:                "test@example.com",
			password:             "123456",
			createAccessTokenErr: errs.ErrInternal,
			wantErr:              errs.ErrInternal,
			calls: expectedCalls{
				repoGet:            true,
				createRefreshToken: true,
				hashRefreshToken:   true,
				createAccessToken:  true,
			},
		},
		{
			name:       "err repoAdd",
			email:      "test@example.com",
			password:   "123456",
			repoAddErr: errs.ErrInternal,
			wantErr:    errs.ErrInternal,
			calls: expectedCalls{
				repoGet:            true,
				createRefreshToken: true,
				hashRefreshToken:   true,
				createAccessToken:  true,
				repoAdd:            true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			if tc.calls.repoGet {
				repo.On(
					"GetAccountByEmail",
					mock.Anything,
					tc.email).
					Return(*account, tc.repoGetErr).
					Once()
			}

			if tc.calls.createRefreshToken {
				tokens.On("CreateRefreshToken").
					Return(refreshToken, tc.createRefreshTokenErr).
					Once()
			}

			if tc.calls.hashRefreshToken {
				tokens.On("HashRefreshToken", mock.Anything).
					Return(refreshTokenHash, tc.hashRefreshTokenErr).
					Once()
			}

			if tc.calls.createAccessToken {
				tokens.On("CreateJWT", mock.Anything).
					Return(accessToken, tc.createAccessTokenErr).
					Once()
			}

			if tc.calls.repoAdd {
				repo.On("AddSession", mock.Anything, mock.Anything, refreshTokenHash).
					Return(*user, tc.repoAddErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			userResult, tokensResult, err := service.Login(context.Background(), tc.email, tc.password)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
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

func TestLogout(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	expiresAt := time.Now().Add(time.Hour)

	refreshTokenHash, err := domain.NewRefreshTokenHash("token", &expiresAt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	userID := uuid.New()

	type expectedCalls struct {
		hashRefreshToken bool
		repo             bool
	}
	cases := []struct {
		name                string
		userID              uuid.UUID
		refreshToken        string
		hashRefreshTokenErr error
		repoErr             error
		waitErr             error
		calls               expectedCalls
	}{
		{
			name:         "valid",
			userID:       userID,
			refreshToken: "token",
			calls: expectedCalls{
				hashRefreshToken: true,
				repo:             true,
			},
		},
		{
			name:         "invalid userID",
			userID:       uuid.Nil,
			refreshToken: "token",
			repoErr:      errs.ErrInvalidInput,
			waitErr:      errs.ErrInvalidInput,
			calls: expectedCalls{
				hashRefreshToken: true,
				repo:             true,
			},
		},
		{
			name:         "empty refreshToken",
			userID:       userID,
			refreshToken: "",
			waitErr:      errs.ErrInvalidInput,
		},
		{
			name:                "error hashing refreshToken",
			userID:              userID,
			refreshToken:        "token",
			hashRefreshTokenErr: errs.ErrInternal,
			waitErr:             errs.ErrInternal,
			calls: expectedCalls{
				hashRefreshToken: true,
			},
		},
		{
			name:         "error repo",
			userID:       userID,
			refreshToken: "token",
			repoErr:      errs.ErrInternal,
			waitErr:      errs.ErrInternal,
			calls: expectedCalls{
				hashRefreshToken: true,
				repo:             true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			if tc.calls.hashRefreshToken {
				tokens.On("HashRefreshToken", mock.Anything).
					Return(refreshTokenHash, tc.hashRefreshTokenErr).
					Once()
			}

			if tc.calls.repo {
				repo.On(
					"RevokeSession",
					mock.Anything,
					tc.userID,
					refreshTokenHash,
				).
					Return(tc.repoErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			err := service.Logout(context.Background(), tc.userID, tc.refreshToken)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}
