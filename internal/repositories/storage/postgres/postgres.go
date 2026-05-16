package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(ctx context.Context, dsn string) (*Repository, error) {
	if strings.TrimSpace(dsn) == "" {
		err := fmt.Errorf("database dsn is empty")
		slog.ErrorContext(ctx, "database dsn is empty", slog.Any("error", err))
		return nil, logger.WrapError(ctx, err)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("parse pgxpool config: %w", err))
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, logger.WrapError(ctx, fmt.Errorf("create pgx pool: %w", err))
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, logger.WrapError(ctx, fmt.Errorf("ping database: %w", err))
	}

	return &Repository{db: pool}, nil
}

func (r *Repository) Close() {
	if r.db != nil {
		r.db.Close()
	}
}

func (r *Repository) CheckHealth(ctx context.Context) error {
	if err := r.db.Ping(ctx); err != nil {
		return logger.WrapError(ctx, fmt.Errorf("ping database: %w", err))
	}
	return nil
}
