package usecase

import (
	"context"
)

type AuthService interface {
}

func (s *Service) Register(ctx context.Context, email, password string) error {
	// if err := s.repo.CheckHealth(ctx); err != nil {
	// 	return logger.WrapError(ctx, err)
	// }
	return nil
}
