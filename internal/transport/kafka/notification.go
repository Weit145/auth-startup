package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/event"
)

type NotificationPublishes interface {
	PublishEmailVerificationRequested(ctx context.Context, event event.EmailRequested) error
}

type NotificationPublisher struct {
	producer *Producer
}

func NewNotificationPublisher(producer *Producer) *NotificationPublisher {
	return &NotificationPublisher{producer: producer}
}

func (p *NotificationPublisher) PublishEmailVerificationRequested(ctx context.Context, evt event.EmailRequested) error {
	if evt.Type == "" {
		evt.Type = event.EmailVerificationRequestedType
	}
	if evt.CreatedAt.IsZero() {
		evt.CreatedAt = time.Now().UTC()
	}

	value, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal email verification requested event: %w", err)
	}

	if err := p.producer.WriteMessages(ctx, []byte(evt.UserID), value); err != nil {
		return fmt.Errorf("publish email verification requested event: %w", err)
	}

	return nil
}
