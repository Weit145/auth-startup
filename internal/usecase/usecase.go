package usecase

import (
	"context"

	"github.com/Weit145/auth-startup/internal/config"
	"github.com/Weit145/auth-startup/internal/infrastructure"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/repositories/storage"
	"github.com/Weit145/auth-startup/internal/transport/kafka"
)

type Service struct {
	repo          storage.Repositories
	inf           infrastructure.Infrastructures
	cfg           *config.Config
	notifications kafka.NotificationPublishes
}

type Services interface {
	CheckHealth(ctx context.Context) (bool, error)
	AuthService
}

func NewServices(repo storage.Repositories, inf infrastructure.Infrastructures, cfg *config.Config, notifications kafka.NotificationPublishes) *Service {
	return &Service{
		repo:          repo,
		inf:           inf,
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
