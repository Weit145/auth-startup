package port

import (
	"context"

	"github.com/Weit145/auth-startup/internal/domain/event"
)

type NotificationPublisher interface {
	AddEvent(ctx context.Context, event event.Event) error
}
