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

func TestRegisterComplete(t *testing.T) {
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

	sessionID := uuid.New()

	type expectedCalls struct {
		createRefresh bool
		hashRefresh   bool
		repository    bool
		createJWT     bool
	}

	cases := []struct {
		name                 string
		sessionID            uuid.UUID
		password             string
		refreshTokenCreatErr error
		refreshTokenHashErr  error
		repoErr              error
		accessTokenCreatErr  error
		waitErr              error
		calls                expectedCalls
	}{
		{
			name:      "valid",
			sessionID: sessionID,
			password:  "password",
			calls: expectedCalls{
				createRefresh: true,
				hashRefresh:   true,
				repository:    true,
				createJWT:     true,
			},
		},
		{
			name:      "invalid sessionID",
			sessionID: uuid.Nil,
			password:  "password",
			waitErr:   errs.ErrInvalidInput,
		},
		{
			name:      "invalid password",
			sessionID: sessionID,
			password:  "12",
			waitErr:   errs.ErrInvalidInput,
		},
		{
			name:      "empty password",
			sessionID: sessionID,
			password:  "",
			waitErr:   errs.ErrInvalidInput,
		},
		{
			name:                 "error refresh token creation",
			sessionID:            sessionID,
			password:             "password",
			refreshTokenCreatErr: errs.ErrInvalidInput,
			waitErr:              errs.ErrInvalidInput,
			calls: expectedCalls{
				createRefresh: true,
			},
		},
		{
			name:                "error refresh token hash",
			sessionID:           sessionID,
			password:            "password",
			refreshTokenHashErr: errs.ErrInvalidInput,
			waitErr:             errs.ErrInvalidInput,
			calls: expectedCalls{
				createRefresh: true,
				hashRefresh:   true,
			},
		},
		{
			name:      "error repo",
			sessionID: sessionID,
			password:  "password",
			repoErr:   errs.ErrInternal,
			waitErr:   errs.ErrInternal,
			calls: expectedCalls{
				createRefresh: true,
				hashRefresh:   true,
				repository:    true,
			},
		},
		{
			name:                "error access token creation",
			sessionID:           sessionID,
			password:            "password",
			accessTokenCreatErr: errs.ErrInternal,
			waitErr:             errs.ErrInternal,
			calls: expectedCalls{
				createRefresh: true,
				hashRefresh:   true,
				repository:    true,
				createJWT:     true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			if tc.calls.createRefresh {
				tokens.On("CreateRefreshToken").
					Return(refreshToken, tc.refreshTokenCreatErr).
					Once()
			}

			if tc.calls.hashRefresh {
				tokens.On("HashRefreshToken", mock.Anything).
					Return(refreshTokenHash, tc.refreshTokenHashErr).
					Once()
			}

			if tc.calls.repository {
				repo.On(
					"RegisterComplete",
					mock.Anything,
					tc.sessionID,
					mock.Anything,
					refreshTokenHash,
				).
					Return(*user, tc.repoErr).
					Once()
			}

			if tc.calls.createJWT {
				tokens.On("CreateJWT", *user).
					Return(accessToken, tc.accessTokenCreatErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			userResult, tokensResult, err := service.RegisterComplete(context.Background(), tc.sessionID, tc.password)
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

func TestRepeatEmail(t *testing.T) {
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

	type expectedCalls struct {
		createEmailVerificationToken bool
		hashEmailVerificationToken   bool
		repo                         bool
	}

	cases := []struct {
		name               string
		email              string
		emailTokenCreatErr error
		emailTokenHashErr  error
		repoErr            error
		waitErr            error
		calls              expectedCalls
	}{
		{
			name:  "valid",
			email: "test@example.com",
			calls: expectedCalls{
				createEmailVerificationToken: true,
				hashEmailVerificationToken:   true,
				repo:                         true,
			},
		},
		{
			name:    "invalid email",
			email:   "1231",
			waitErr: errs.ErrInvalidInput,
			calls: expectedCalls{
				createEmailVerificationToken: true,
				hashEmailVerificationToken:   true,
			},
		},
		{
			name:               "error creating email verification token",
			email:              "test@example.com",
			emailTokenCreatErr: errs.ErrInvalidInput,
			waitErr:            errs.ErrInvalidInput,
			calls: expectedCalls{
				createEmailVerificationToken: true,
			},
		},
		{
			name:              "error hashing email verification token",
			email:             "test@example.com",
			emailTokenHashErr: errs.ErrInvalidInput,
			waitErr:           errs.ErrInvalidInput,
			calls: expectedCalls{
				createEmailVerificationToken: true,
				hashEmailVerificationToken:   true,
			},
		},
		{
			name:    "error saving email verification token",
			email:   "test@example.com",
			repoErr: errs.ErrInternal,
			waitErr: errs.ErrInternal,
			calls: expectedCalls{
				createEmailVerificationToken: true,
				hashEmailVerificationToken:   true,
				repo:                         true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			if tc.calls.createEmailVerificationToken {
				tokens.On("CreateEmailVerificationToken").
					Return(token, tc.emailTokenCreatErr).
					Once()
			}
			if tc.calls.hashEmailVerificationToken {
				tokens.On("HashEmailVerificationToken", mock.Anything).
					Return(tokenHash, tc.emailTokenHashErr).
					Once()
			}
			if tc.calls.repo {
				repo.On(
					"RepeatEmail",
					mock.Anything,
					tc.email,
					mock.Anything,
					tokenHash,
				).
					Return(tc.repoErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			err := service.RepeatEmail(context.Background(), tc.email)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}
