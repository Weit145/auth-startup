package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/google/uuid"
)

func TestUserDomain(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name    string
		id      uuid.UUID
		email   string
		role    string
		wantErr error
	}{
		{
			name:    "valid user",
			id:      id,
			email:   "test@example.com",
			role:    "admin",
			wantErr: nil,
		},
		{
			name:    "invalid id",
			id:      uuid.Nil,
			email:   "test@example.com",
			role:    "admin",
			wantErr: errs.ErrInvalidInput,
		},
		{
			name:    "invalid role",
			id:      id,
			email:   "test@example.com",
			role:    "iiiik",
			wantErr: errs.ErrInvalidInput,
		},
		{
			name:    "invalid email",
			id:      id,
			email:   "invalid-email",
			role:    "admin",
			wantErr: errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			user, err := domain.NewUser(
				tc.id,
				tc.email,
				tc.role,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewUser() error = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if user.ID() != tc.id {
				t.Errorf(
					"ID() = %v, want %v",
					user.ID(),
					tc.id,
				)
			}
			if user.Email() != tc.email {
				t.Errorf(
					"Email() = %v, want %v",
					user.Email(),
					tc.email,
				)
			}
			if user.Role() != tc.role {
				t.Errorf(
					"Role() = %v, want %v",
					user.Role(),
					tc.role,
				)
			}
		})
	}
}

func TestCreateUserAccountDomain(t *testing.T) {
	password := "123123"

	passwordHash, err := domain.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	emailVerifiedAt := time.Now()
	id := uuid.New()

	cases := []struct {
		name            string
		id              uuid.UUID
		email           string
		passwordHash    string
		role            string
		emailVerifiedAt *time.Time
		wantErr         error
	}{
		{
			name:            "valid account",
			id:              id,
			email:           "test@example.com",
			passwordHash:    passwordHash,
			role:            "admin",
			emailVerifiedAt: &emailVerifiedAt,
		},
		{
			name:            "empty id",
			id:              uuid.Nil,
			email:           "test@example.com",
			passwordHash:    passwordHash,
			role:            "admin",
			emailVerifiedAt: &emailVerifiedAt,
			wantErr:         errs.ErrInvalidInput,
		},
		{
			name:            "empty password hash",
			id:              id,
			email:           "test@example.com",
			passwordHash:    "",
			role:            "admin",
			emailVerifiedAt: &emailVerifiedAt,
			wantErr:         errs.ErrInvalidInput,
		},
		{
			name:         "missing verification time",
			id:           id,
			email:        "test@example.com",
			passwordHash: passwordHash,
			role:         "admin",
			wantErr:      errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			account, err := domain.CreateUserAccount(
				tc.id,
				tc.email,
				tc.passwordHash,
				tc.role,
				tc.emailVerifiedAt,
			)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CreateUserAccount() error = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}

			if err := account.CheckVerifiedPassword(password); err != nil {
				t.Errorf("CheckVerifiedPassword() error = %v", err)
			}
		})
	}
}

func TestNewUserAccountDomain(t *testing.T) {
	cases := []struct {
		name     string
		email    string
		password string
		role     string
		wantErr  error
	}{
		{
			name:     "valid account",
			email:    "test@example.com",
			password: "123123",
			role:     "admin",
		},
		{
			name:     "valid account",
			email:    "test@example.com",
			password: "123123",
			role:     "user",
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
			role:     "admin",
			wantErr:  errs.ErrInvalidInput,
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
			role:     "user",
			wantErr:  errs.ErrInvalidInput,
		},
		{
			name:     "empty email",
			email:    "",
			password: "123123",
			role:     "admin",
			wantErr:  errs.ErrInvalidInput,
		},
		{
			name:     "empty email",
			email:    "",
			password: "123123",
			role:     "user",
			wantErr:  errs.ErrInvalidInput,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var account *domain.Account
			var err error
			switch tc.role {
			case "user":
				account, err = domain.NewUserAccount(
					tc.email,
					tc.password,
				)
			case "admin":
				account, err = domain.NewAdminAccount(
					tc.email,
					tc.password,
				)
			}

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("account constructor error = %v, want %v",
					err,
					tc.wantErr,
				)
			}
			if err != nil {
				return
			}

			if err := account.CheckVerifiedPassword(tc.password); err != nil {
				t.Errorf("CheckVerifiedPassword() error = %v", err)
			}

			user := account.User()
			if user.Role() != tc.role {
				t.Errorf(
					"Role() = %v, want %v",
					user.Role(),
					tc.role,
				)
			}
			if user.Email() != tc.email {
				t.Errorf(
					"Email() = %v, want %v",
					user.Email(),
					tc.email,
				)
			}

		})
	}
}
