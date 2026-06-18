package domain

import (
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/lib/valid"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	id    uuid.UUID
	email string
	name  string
	role  string
}

func (u *User) ID() uuid.UUID {
	return u.id
}

func (u *User) Email() string {
	return u.email
}

func (u *User) Name() string {
	return u.name
}

func (u *User) Role() string {
	return u.role
}

func NewUser(id uuid.UUID, email, name, role string) (*User, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("id cannot be empty")
	}

	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	name, err = valid.NormalizeValue(name)
	if err != nil {
		return nil, fmt.Errorf("invalid name: %w", err)
	}

	role, err = valid.NormalizeValue(role)
	if err != nil {
		return nil, fmt.Errorf("invalid role: %w", err)
	}

	if role != "user" && role != "admin" {
		return nil, fmt.Errorf("invalid role %q: %w", role, errs.ErrInvalidInput)
	}

	return &User{
		id:    id,
		email: email,
		name:  name,
		role:  role,
	}, nil
}

type Account struct {
	user            User
	passwordHash    string
	emailVerifiedAt *time.Time
}

func (a *Account) PasswordHash() string {
	return a.passwordHash
}

func (a *Account) User() User {
	return a.user
}

func (a *Account) CheckVerifiedPassword(password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(a.PasswordHash()), []byte(password))
	if err != nil {
		return errs.ErrUnauthorized
	}
	return nil
}

func NewUserAccount(email, password, name string) (*Account, error) {

	id := uuid.New()

	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	password, err = valid.NormalizePassword(password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	passwordHashStr := string(passwordHash)

	name, err = valid.NormalizeValue(name)
	if err != nil {
		return nil, fmt.Errorf("invalid name: %w", err)
	}

	return &Account{
		user: User{
			id:    id,
			email: email,
			name:  name,
			role:  "user",
		},
		passwordHash: passwordHashStr,
	}, nil
}

func NewAdminAccount(email, name, password string) (*Account, error) {

	id := uuid.New()

	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	name, err = valid.NormalizeValue(name)
	if err != nil {
		return nil, fmt.Errorf("invalid name: %w", err)
	}

	password, err = valid.NormalizePassword(password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	passwordHashStr := string(passwordHash)
	return &Account{
		user: User{
			id:    id,
			email: email,
			name:  name,
			role:  "admin",
		},
		passwordHash: passwordHashStr,
	}, nil
}

func CreateUserAccount(id uuid.UUID, email, passwordHash, name, role string, emailVerifiedAt *time.Time) (*Account, error) {

	if id == uuid.Nil {
		return nil, fmt.Errorf("id cannot be empty")
	}

	email, err := valid.NormalizeEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	passwordHash, err = valid.NormalizeValue(passwordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid password hash: %w", err)
	}

	name, err = valid.NormalizeValue(name)
	if err != nil {
		return nil, fmt.Errorf("invalid name: %w", err)
	}

	role, err = valid.NormalizeValue(role)
	if err != nil {
		return nil, fmt.Errorf("invalid role: %w", err)
	}

	if role != "user" && role != "admin" {
		return nil, fmt.Errorf("invalid role %q: %w", role, errs.ErrInvalidInput)
	}

	if emailVerifiedAt == nil {
		return nil, fmt.Errorf("invalid emailVerifiedAt")
	}

	return &Account{
		user: User{
			id:    id,
			email: email,
			name:  name,
			role:  role,
		},
		passwordHash:    passwordHash,
		emailVerifiedAt: emailVerifiedAt,
	}, nil
}

func HashPassword(password string) (string, error) {
	password, err := valid.NormalizePassword(password)
	if err != nil {
		return "", fmt.Errorf("invalid password: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	passwordHashStr := string(passwordHash)
	return passwordHashStr, nil
}
