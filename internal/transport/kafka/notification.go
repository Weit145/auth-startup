package kafka

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Weit145/auth-startup/internal/domain"
	"github.com/Weit145/auth-startup/internal/transport/kafka/event"
)

type NotificationPublisher struct {
	producer *Producer
}

func NewNotificationPublisher(producer *Producer) *NotificationPublisher {
	return &NotificationPublisher{producer: producer}
}

func (p *NotificationPublisher) PublishEvent(ctx context.Context, evt domain.Email, url string) error {
	emailEvent, err := event.NewEmailVer(ctx, evt, url)
	if err != nil {
		return fmt.Errorf("create event: %w", err)
	}
	value, err := json.Marshal(emailEvent)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	if err := p.producer.WriteMessages(ctx, []byte(emailEvent.UserID), value); err != nil {
		return fmt.Errorf("publish  event: %w", err)
	}

	return nil
}
