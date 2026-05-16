package usecase

import (
	"context"

	"github.com/Weit145/auth-startup/internal/infrastructure"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/repositories/storage"
)

type Service struct {
	repo storage.Repositories
	inf  infrastructure.Infrastructures
}

type Services interface {
	CheckHealth(ctx context.Context) error
	AuthService
}

func NewServices(repo storage.Repositories, inf infrastructure.Infrastructures) *Service {
	return &Service{
		repo: repo,
		inf:  inf,
	}
}

func (s *Service) CheckHealth(ctx context.Context) error {
	if err := s.repo.CheckHealth(ctx); err != nil {
		return logger.WrapError(ctx, err)
	}
	return nil
}
