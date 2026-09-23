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

func TestPasswordRequest(t *testing.T) {
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
					"PasswordRequest",
					mock.Anything,
					tc.email,
					tokenHash,
					mock.Anything,
				).
					Return(tc.repoErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			err := service.PasswordRequest(context.Background(), tc.email)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}

func TestPasswordConfirm(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	expiresAt := time.Now().Add(time.Hour)

	tokenHash, err := domain.NewEmailVerificationTokenHash("hash", &expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	UserID := uuid.New()
	user, err := domain.NewUser(UserID, "test@example.com", "user")
	if err != nil {
		t.Fatal(err)
	}

	type expectedCalls struct {
		hashEmailVerificationToken bool
		repo                       bool
	}

	cases := []struct {
		name              string
		userID            uuid.UUID
		token             string
		newPassword       string
		emailTokenHashErr error
		repoErr           error
		waitErr           error
		calls             expectedCalls
	}{
		{
			name:        "valid",
			userID:      UserID,
			token:       "token",
			newPassword: "password",
			calls: expectedCalls{
				hashEmailVerificationToken: true,
				repo:                       true,
			},
		},
		{
			name:        "invalid userID",
			userID:      uuid.Nil,
			token:       "token",
			newPassword: "password",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "invalid token",
			userID:      UserID,
			token:       "",
			newPassword: "password",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "invalid password",
			userID:      UserID,
			token:       "token",
			newPassword: "123",
			waitErr:     errs.ErrInvalidInput,
			calls: expectedCalls{
				hashEmailVerificationToken: true,
			},
		},
		{
			name:        "empty password",
			userID:      UserID,
			token:       "token",
			newPassword: "",
			waitErr:     errs.ErrInvalidInput,
			calls: expectedCalls{
				hashEmailVerificationToken: true,
			},
		},
		{
			name:              "error hash email verification token",
			userID:            UserID,
			token:             "token",
			newPassword:       "password",
			emailTokenHashErr: errs.ErrInternal,
			waitErr:           errs.ErrInternal,
			calls: expectedCalls{
				hashEmailVerificationToken: true,
			},
		},
		{
			name:        "error repo",
			userID:      UserID,
			token:       "token",
			newPassword: "password",
			repoErr:     errs.ErrInternal,
			waitErr:     errs.ErrInternal,
			calls: expectedCalls{
				hashEmailVerificationToken: true,
				repo:                       true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tokens := mocks.NewTokenProvider(t)
			repo := mocks.NewRepository(t)

			if tc.calls.hashEmailVerificationToken {
				tokens.On("HashEmailVerificationToken", mock.Anything).
					Return(tokenHash, tc.emailTokenHashErr).
					Once()
			}

			if tc.calls.repo {
				repo.On(
					"PasswordConfirm",
					mock.Anything,
					tc.userID,
					tokenHash,
					mock.Anything,
				).
					Return(*user, tc.repoErr).
					Once()
			}
			service := usecase.NewServices(repo, tokens, cfg)

			err := service.PasswordConfirm(context.Background(), tc.userID, tc.token, tc.newPassword)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}

func TestChangePassword(t *testing.T) {
	cfg := usecase.Settings{
		EmailVerificationURL:      "https://example.com/verify",
		RefreshTokenTTL:           24 * time.Hour,
		EmailVerificationTokenTTL: 15 * time.Minute,
		ShortSessionTTL:           15 * time.Minute,
	}

	userID := uuid.New()

	type expectedCalls struct {
		repo bool
	}

	cases := []struct {
		name        string
		userID      uuid.UUID
		oldPassword string
		newPassword string
		repoErr     error
		waitErr     error
		calls       expectedCalls
	}{
		{
			name:        "valid",
			userID:      userID,
			oldPassword: "123123",
			newPassword: "123456",
			calls: expectedCalls{
				repo: true,
			},
		},
		{
			name:        "invalid userID",
			userID:      uuid.Nil,
			oldPassword: "123123",
			newPassword: "123456",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "invalid old password",
			userID:      userID,
			oldPassword: "123",
			newPassword: "123456",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "invalid new password",
			userID:      userID,
			oldPassword: "123123",
			newPassword: "123",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "empty old password",
			userID:      userID,
			oldPassword: "",
			newPassword: "123123",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "empty new password",
			userID:      userID,
			oldPassword: "123123",
			newPassword: "",
			waitErr:     errs.ErrInvalidInput,
		},
		{
			name:        "error repo",
			userID:      userID,
			oldPassword: "123123",
			newPassword: "123456",
			repoErr:     errs.ErrInternal,
			waitErr:     errs.ErrInternal,
			calls: expectedCalls{
				repo: true,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepository(t)
			tokens := mocks.NewTokenProvider(t)

			user := domain.User{}

			if tc.calls.repo {
				repo.On(
					"ChangePassword",
					mock.Anything,
					tc.userID,
					mock.Anything,
					mock.Anything,
				).Return(user, tc.repoErr).
					Once()
			}

			service := usecase.NewServices(repo, tokens, cfg)

			err := service.ChangePassword(context.Background(), tc.userID, tc.oldPassword, tc.newPassword)
			if !errors.Is(err, tc.waitErr) {
				t.Fatalf("expected error %v, got %v", tc.waitErr, err)
			}
		})
	}
}
