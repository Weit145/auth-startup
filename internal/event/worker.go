package event

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
)

type KafkaRequest interface {
	WriteMessages(ctx context.Context, key, value []byte) error
}

type Repository interface {
	SetEventError(ctx context.Context, eventID uuid.UUID) error
	ClaimPendingOutbox(ctx context.Context, limit int) ([]event.Event, error)
	ReleaseEventForRetry(ctx context.Context, eventID uuid.UUID, lastError string) error
	SetEventPublished(ctx context.Context, eventID uuid.UUID) error
}

type job struct {
	event event.Event
}

type WorkerPool struct {
	jobs chan job
	wg   sync.WaitGroup
	req  KafkaRequest
	repo Repository
	num  int
	done <-chan struct{}
}

func NewWorkerPool(
	num int,
	req KafkaRequest,
	repo Repository,
) (*WorkerPool, error) {
	if num < 1 {
		return nil, fmt.Errorf("worker count must be positive")
	}
	if req == nil {
		return nil, fmt.Errorf("request client is nil")
	}
	if repo == nil {
		return nil, fmt.Errorf("repository is nil")
	}

	return &WorkerPool{
		jobs: make(chan job, num),
		req:  req,
		repo: repo,
		num:  num,
	}, nil
}

func (p *WorkerPool) Run(ctx context.Context) {
	p.done = ctx.Done()
	for id := 1; id <= p.num; id++ {
		p.wg.Add(1)
		go p.worker(ctx, id)
	}
	p.wg.Add(1)
	go p.runPoller(ctx)
}

func (p *WorkerPool) runPoller(ctx context.Context) {
	defer p.wg.Done()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			count, err := p.poller(ctx)

			if count == 0 || err != nil {
				timer.Reset(pollInterval)
			} else {
				timer.Reset(0)
			}

			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.ErrorContext(
					logger.ErrorCtx(ctx, err),
					"failed to poll outbox",
				)
			}
		}
	}
}
