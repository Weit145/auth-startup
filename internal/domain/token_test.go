package domain

import (
	"context"
	"testing"
	"time"
)

func TestTokenExpiresAt(t *testing.T) {
	token, err := NewToken(context.Background(), "token", nil)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	if _, ok := token.ExpiresAt(); ok {
		t.Fatal("token without expiration reported an expiration")
	}

	token.CreateExpiresAt(time.Hour)

	expiresAt, ok := token.ExpiresAt()
	if !ok {
		t.Fatal("token expiration is missing")
	}
	if expiresAt.Before(time.Now().UTC()) {
		t.Fatalf("token expiration is in the past: %s", expiresAt)
	}
}

func TestTokenIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{name: "without expiration", want: false},
		{name: "expired", expiresAt: timePointer(time.Now().UTC().Add(-time.Minute)), want: true},
		{name: "active", expiresAt: timePointer(time.Now().UTC().Add(time.Minute)), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := NewToken(context.Background(), "token", tt.expiresAt)
			if err != nil {
				t.Fatalf("create token: %v", err)
			}

			if got := token.IsExpired(); got != tt.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
