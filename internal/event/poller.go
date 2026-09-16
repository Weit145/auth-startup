package event

import (
	"context"
	"fmt"
	"time"

	"github.com/Weit145/auth-startup/internal/logger"
)

const (
	pollInterval = 500 * time.Millisecond
)

func (p *WorkerPool) poller(ctx context.Context) (int, error) {
	select {
	case <-p.done:
		return 0, logger.WrapError(ctx, fmt.Errorf("stopped worker pool"))
	default:
	}

	evnts, err := p.repo.ClaimPendingOutbox(ctx, p.num)
	if err != nil {
		return 0, logger.WrapError(ctx, fmt.Errorf("claim pending outbox: %w", err))
	}

	for _, evt := range evnts {
		queuedJob := job{event: evt}
		select {
		case p.jobs <- queuedJob:
		case <-p.done:
			return 0, logger.WrapError(ctx, fmt.Errorf("stopped worker pool"))
		case <-ctx.Done():
			return 0, logger.WrapError(ctx, fmt.Errorf("Stopped: %w", ctx.Err()))
		}
	}
	return len(evnts), nil
}

func (p *WorkerPool) Wait() {
	p.wg.Wait()
}
