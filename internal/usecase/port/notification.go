package port

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain"
)

type NotificationPublisher interface {
	PublishEvent(ctx context.Context, evt domain.Email, url string) error
}
