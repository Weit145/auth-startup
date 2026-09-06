package event

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/event/dto"
	"github.com/Weit145/auth-startup/internal/logger"
)

func (p *WorkerPool) worker(ctx context.Context, id int) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			err := p.process(ctx, job.event)
			if err != nil {
				slog.ErrorContext(logger.ErrorCtx(ctx, err), "failed to process event",
					slog.Int("worker_id", id), slog.String("event_id", job.event.EventID().String()), slog.Any("error", err))
			}

		}
	}
}

func (p *WorkerPool) process(ctx context.Context, evt event.Event) error {
	ctx = logger.WithLogID(ctx, evt.UserID())
	ctx = logger.WithLogEmail(ctx, evt.Email())

	switch evt.TypeEvent() {
	case event.EmailVerificationRequestedType:
		emailEvent, err := dto.NewEmailRequested(ctx, evt)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("create email verification payload: %w", err))
		}
		value, err := json.Marshal(emailEvent)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("marshal event: %w", err))
		}
		if err := p.repo.SetDispatchingOutbox(ctx, evt); err != nil {
			return logger.WrapError(ctx, fmt.Errorf("set dispatching outbox: %w", err))
		}
		if err := p.req.WriteMessages(ctx, []byte(emailEvent.UserID), value); err != nil {
			if err := p.repo.SetEventError(ctx, evt.EventID()); err != nil {
				return logger.WrapError(ctx, fmt.Errorf("set event error: %w", err))
			}
			return logger.WrapError(ctx, fmt.Errorf("publish event: %w", err))
		}
	case event.ResetPasswordType:
		resetPasswordEvent, err := dto.NewEmailRequested(ctx, evt)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("create reset password event: %w", err))
		}
		value, err := json.Marshal(resetPasswordEvent)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("marshal event: %w", err))
		}
		if err := p.repo.SetDispatchingOutbox(ctx, evt); err != nil {
			return logger.WrapError(ctx, fmt.Errorf("set dispatching outbox: %w", err))
		}
		if err := p.req.WriteMessages(ctx, []byte(resetPasswordEvent.UserID), value); err != nil {
			if err := p.repo.SetEventError(ctx, evt.EventID()); err != nil {
				return logger.WrapError(ctx, fmt.Errorf("set event error: %w", err))
			}
			return logger.WrapError(ctx, fmt.Errorf("publish event: %w", err))
		}
	case event.ReapitEmailVerificationType:
		emailVerificationEvent, err := dto.NewEmailRequested(ctx, evt)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("create email verification event: %w", err))
		}
		value, err := json.Marshal(emailVerificationEvent)
		if err != nil {
			return logger.WrapError(ctx, fmt.Errorf("marshal event: %w", err))
		}
		if err := p.repo.SetDispatchingOutbox(ctx, evt); err != nil {
			return logger.WrapError(ctx, fmt.Errorf("set dispatching outbox: %w", err))
		}
		if err := p.req.WriteMessages(ctx, []byte(emailVerificationEvent.UserID), value); err != nil {
			if err := p.repo.SetEventError(ctx, evt.EventID()); err != nil {
				return logger.WrapError(ctx, fmt.Errorf("set event error: %w", err))
			}
			return logger.WrapError(ctx, fmt.Errorf("publish event: %w", err))
		}
	default:
		return logger.WrapError(ctx, fmt.Errorf("unknown event type: %q", evt.TypeEvent().String()))
	}
	return nil
}
