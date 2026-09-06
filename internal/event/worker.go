package event

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/Weit145/auth-startup/internal/domain/event"
	"github.com/Weit145/auth-startup/internal/logger"
)

type KafkaRequest interface {
	WriteMessages(ctx context.Context, key, value []byte) error
}

type Repository interface {
	SetDispatchingOutbox(ctx context.Context, event event.Event) error
	SetEventError(ctx context.Context, eventID uuid.UUID) error
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

func NewWorkerPool(num int, req KafkaRequest, repo Repository) (*WorkerPool, error) {
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
}

func (p *WorkerPool) AddEvent(ctx context.Context, event event.Event) error {
	select {
	case <-p.done:
		return logger.WrapError(ctx, fmt.Errorf("add event to stopped worker pool"))
	default:
	}

	queuedJob := job{event: event}

	select {
	case p.jobs <- queuedJob:
		return nil
	case <-p.done:
		return logger.WrapError(ctx, fmt.Errorf("add event to stopped worker pool"))
	case <-ctx.Done():
		return logger.WrapError(ctx, fmt.Errorf("add event to worker pool: %w", ctx.Err()))
	}
}

func (p *WorkerPool) Wait() {
	p.wg.Wait()
}
