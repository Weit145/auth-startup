package kafka

import (
	"context"
	"log/slog"
	"time"

	"github.com/segmentio/kafka-go"
)

type Producer struct {
	writer *kafka.Writer
}

func NewProducer(brokers []string, topic string) *Producer {
	writer := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  topic,
		Balancer:               &kafka.Hash{},
		RequiredAcks:           kafka.RequireAll,
		Async:                  false,
		MaxAttempts:            3,
		ReadTimeout:            10 * time.Second,
		WriteTimeout:           10 * time.Second,
		AllowAutoTopicCreation: true,
	}
	slog.Info("Kafka producer created", "brokers", brokers, "topic", topic)
	return &Producer{writer: writer}
}

func (p *Producer) WriteMessages(ctx context.Context, key, value []byte) error {
	message := kafka.Message{
		Key:   key,
		Value: value,
	}
	return p.writer.WriteMessages(ctx, message)
}

func (p *Producer) Close() error {
	slog.Info("Kafka producer closed")
	return p.writer.Close()
}
