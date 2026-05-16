package domain

import (
	"fmt"

	"github.com/google/uuid"
)

type User struct {
	id    uuid.UUID
	email string
	name  string
	role  string
}

func NewUser(email, name string) (*User, error) {

	id := uuid.New()

	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	return &User{
		id:    id,
		email: email,
		name:  name,
		role:  "user",
	}, nil
}

func NewAdminUser(email, name string) (*User, error) {

	id := uuid.New()

	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	return &User{
		id:    id,
		email: email,
		name:  name,
		role:  "admin",
	}, nil
}

func UserFromID(id uuid.UUID, email, name, role string) (*User, error) {

	if id == uuid.Nil {
		return nil, fmt.Errorf("id cannot be empty")
	}

	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	if role != "user" && role != "admin" {
		return nil, fmt.Errorf("invalid role: %s", role)
	}

	return &User{
		id:    id,
		email: email,
		name:  name,
		role:  role,
	}, nil
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
