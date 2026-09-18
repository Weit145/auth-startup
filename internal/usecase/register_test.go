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

func TestRegisterRequest(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	expiresAt := time.Now().Add(time.Hour)

	token, err := domain.NewEmailVerificationToken("token", nil)
	if err != nil {
		t.Fatal(err)
	}

	tokenHash, err := domain.NewEmailVerificationTokenHash("hash", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		email        string
		tokenErr     error
		tokenHashErr error
		repoErr      error
		waitErr      error
	}{
		{
			name:    "valid",
			email:   "test@example.com",
			waitErr: nil,
		},
		{
			name:    "invalid email",
			email:   "test",
			waitErr: errs.ErrInvalidInput,
		},
		{
			name:     "token error",
			email:    "test@example.com",
			tokenErr: errs.ErrInvalidInput,
			waitErr:  errs.ErrInvalidInput,
		},
		{
			name:    "repo error",
			email:   "test@example.com",
			repoErr: errs.ErrInternal,
			waitErr: errs.ErrInternal,
		},
		{
			name:         "token hash error",
			email:        "test@example.com",
			tokenHashErr: errs.ErrInvalidInput,
			waitErr:      errs.ErrInvalidInput,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			tokens.
				On("CreateEmailVerificationToken").
				Return(token, tc.tokenErr).
				Once()

			if tc.tokenErr == nil {
				tokens.
					On("HashEmailVerificationToken", mock.Anything).
					Return(tokenHash, tc.tokenHashErr).
					Once()
			}

			if tc.tokenErr == nil &&
				tc.tokenHashErr == nil &&
				tc.email == "test@example.com" {

				repo.
					On(
						"RegisterRequest",
						mock.Anything,
						mock.Anything,
						mock.Anything,
						tokenHash,
					).
					Return(tc.repoErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)
			ctx := context.Background()

			err := service.RegisterRequest(ctx, tc.email)
			if !errors.Is(err, tc.waitErr) {
				t.Errorf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}

func TestConfirmEmail(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	expiresAt := time.Now().Add(time.Hour)

	token, err := domain.NewEmailVerificationToken("token", nil)
	if err != nil {
		t.Fatal(err)
	}

	tokenHash, err := domain.NewEmailVerificationTokenHash("hash", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	shortSessionToken, err := domain.NewShortSessionToken("session", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	shortSessionTokenHash, err := domain.NewShortSessionTokenHash(uuid.New(), "sessionHash", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	accessToken, err := domain.NewAccessToken("accessToken", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		token             string
		userID            uuid.UUID
		tokenEmailHashErr error
		sessionCreateErr  error
		sessionHashErr    error
		repoErr           error
		accessCreateErr   error
		waitErr           error
	}{
		{
			name:    "valid",
			token:   token.Value(),
			userID:  uuid.New(),
			waitErr: nil,
		},
		{
			name:    "invalid token",
			token:   "",
			userID:  uuid.New(),
			waitErr: errs.ErrInvalidInput,
		},
		{
			name:    "invalid user ID",
			token:   token.Value(),
			userID:  uuid.Nil,
			repoErr: errs.ErrInvalidInput,
			waitErr: errs.ErrInvalidInput,
		},
		{
			name:              "email token hash error",
			token:             token.Value(),
			userID:            uuid.New(),
			tokenEmailHashErr: errs.ErrInternal,
			waitErr:           errs.ErrInternal,
		},
		{
			name:             "short session token creation error",
			token:            token.Value(),
			userID:           uuid.New(),
			sessionCreateErr: errs.ErrInternal,
			waitErr:          errs.ErrInternal,
		},
		{
			name:           "short session token hash error",
			token:          token.Value(),
			userID:         uuid.New(),
			sessionHashErr: errs.ErrInternal,
			waitErr:        errs.ErrInternal,
		},
		{
			name:    "repository error",
			token:   token.Value(),
			userID:  uuid.New(),
			repoErr: errs.ErrInternal,
			waitErr: errs.ErrInternal,
		},
		{
			name:            "access token creation error",
			token:           token.Value(),
			userID:          uuid.New(),
			accessCreateErr: errs.ErrInternal,
			waitErr:         errs.ErrInternal,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			var user domain.User
			if tc.userID != uuid.Nil {
				domainUser, err := domain.NewUser(tc.userID, "test@example.com", "user")
				if err != nil {
					t.Fatal(err)
				}
				user = *domainUser
			}

			if tc.token != "" {
				tokens.
					On("HashEmailVerificationToken", mock.Anything).
					Return(tokenHash, tc.tokenEmailHashErr).
					Once()
			}

			if tc.token != "" && tc.tokenEmailHashErr == nil {
				tokens.
					On("CreateShortSessionToken").
					Return(shortSessionToken, tc.sessionCreateErr).
					Once()
			}

			if tc.token != "" && tc.tokenEmailHashErr == nil && tc.sessionCreateErr == nil {
				tokens.
					On("HashShortSessionToken", mock.Anything).
					Return(shortSessionTokenHash, tc.sessionHashErr).
					Once()
			}

			if tc.token != "" && tc.tokenEmailHashErr == nil &&
				tc.sessionCreateErr == nil && tc.sessionHashErr == nil {
				repo.
					On(
						"ConfirmEmail",
						mock.Anything,
						tc.userID,
						shortSessionTokenHash,
						tokenHash,
					).
					Return(user, shortSessionTokenHash.ID(), tc.repoErr).
					Once()
			}

			if tc.token != "" && tc.tokenEmailHashErr == nil &&
				tc.sessionCreateErr == nil && tc.sessionHashErr == nil && tc.repoErr == nil {
				tokens.
					On("CreateJWTWithSession", user, shortSessionTokenHash.ID()).
					Return(accessToken, tc.accessCreateErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)
			result, err := service.ConfirmEmail(context.Background(), tc.token, tc.userID)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
			if err == nil && result.Value() != accessToken.Value() {
				t.Fatalf("expected access token %q, got %q", accessToken.Value(), result.Value())
			}
		})
	}
}
