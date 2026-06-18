package usecase

import (
	"context"
	"time"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/usecase/port"
)

type Settings struct {
	EmailVerificationURL      string
	RefreshTokenTTL           time.Duration
	EmailVerificationTokenTTL time.Duration
}

type Service struct {
	repo          port.Repository
	tokens        port.TokenProvider
	cfg           Settings
	notifications port.NotificationPublisher
}

func NewServices(repo port.Repository, tokens port.TokenProvider, cfg Settings, notifications port.NotificationPublisher) *Service {
	return &Service{
		repo:          repo,
		tokens:        tokens,
		cfg:           cfg,
		notifications: notifications,
	}
}

func (s *Service) CheckHealth(ctx context.Context) (bool, error) {
	if err := s.repo.CheckHealth(ctx); err != nil {
		return false, logger.WrapError(ctx, err)
	}
	return true, nil
}
