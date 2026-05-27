package domain

import (
	"context"
	"fmt"
	"time"

	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	id              uuid.UUID
	passwordHash    *string
	email           string
	name            string
	role            string
	emailVerifiedAt *time.Time
}

func NewUser(ctx context.Context, email, password, name string) (*User, error) {

	id := uuid.New()

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email cannot be empty"))
	}

	if password == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("password cannot be empty"))
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("hash password: %w", err))
	}
	passwordHashStr := string(passwordHash)

	if name == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("name cannot be empty"))
	}

	return &User{
		id:           id,
		passwordHash: &passwordHashStr,
		email:        email,
		name:         name,
		role:         "user",
	}, nil
}

func NewAdminUser(ctx context.Context, email, name, password string) (*User, error) {

	id := uuid.New()

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email cannot be empty"))
	}

	if name == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("name cannot be empty"))
	}

	if password == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("password cannot be empty"))
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("hash password: %w", err))
	}
	passwordHashStr := string(passwordHash)
	return &User{
		id:           id,
		passwordHash: &passwordHashStr,
		email:        email,
		name:         name,
		role:         "admin",
	}, nil
}

func UserFromID(ctx context.Context, id uuid.UUID, email, name, role string) (*User, error) {
	if id == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("id cannot be empty"))
	}

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email cannot be empty"))
	}

	if name == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("name cannot be empty"))
	}

	if role != "user" && role != "admin" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid role: %s", role))
	}

	return &User{
		id:    id,
		email: email,
		name:  name,
		role:  role,
	}, nil
}

func UserNotVerification(ctx context.Context, id uuid.UUID, email, passwordHash, name, role string, emailVerifiedAt *time.Time) (*User, error) {

	if id == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("id cannot be empty"))
	}

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email cannot be empty"))
	}

	if name == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("name cannot be empty"))
	}

	if role != "user" && role != "admin" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid role: %s", role))
	}

	if emailVerifiedAt != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid emailVerifiedAt"))
	}

	return &User{
		id:              id,
		passwordHash:    &passwordHash,
		email:           email,
		name:            name,
		role:            role,
		emailVerifiedAt: emailVerifiedAt,
	}, nil
}

func UserVerification(ctx context.Context, id uuid.UUID, email, passwordHash, name, role string, emailVerifiedAt *time.Time) (*User, error) {

	if id == uuid.Nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("id cannot be empty"))
	}

	if email == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("email cannot be empty"))
	}

	if name == "" {
		return nil, logger.WrapError(ctx, fmt.Errorf("name cannot be empty"))
	}

	if role != "user" && role != "admin" {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid role: %s", role))
	}

	if emailVerifiedAt == nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("invalid emailVerifiedAt"))
	}

	return &User{
		id:              id,
		passwordHash:    &passwordHash,
		email:           email,
		name:            name,
		role:            role,
		emailVerifiedAt: emailVerifiedAt,
	}, nil
}

func (u *User) CheckVerifiedPassword(ctx context.Context, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash()), []byte(password))
	if err != nil {
		return logger.WrapError(ctx, errs.ErrUnauthorized)
	}
	return nil
}

func (u *User) ID() uuid.UUID {
	return u.id
}

func (u *User) PasswordHash() string {
	return *u.passwordHash
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
