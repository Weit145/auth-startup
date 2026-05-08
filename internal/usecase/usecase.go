package usecase

import (
	"context"

	"github.com/Weit145/auth-startup/internal/repositories/storage"
)

type Service struct {
	repo storage.Repositories
}

type Services interface {
	CheckHealth(ctx context.Context) error
}

func NewServices(repo storage.Repositories) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) CheckHealth(ctx context.Context) error {
	return s.repo.CheckHealth(ctx)
}
