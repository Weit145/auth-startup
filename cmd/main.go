package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Weit145/auth-startup/internal/config"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/repositories/storage/postgres"
	v1 "github.com/Weit145/auth-startup/internal/transport/grpc/v1"
	"github.com/Weit145/auth-startup/internal/usecase"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		slog.ErrorContext(logger.ErrorCtx(context.Background(), err), "service failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	//Init config
	cfg := config.InitConfig()

	//Init logger
	logger.InitLogging(cfg.Log.Level)
	slog.Info("Init logger")
	slog.Info("Init config")

	//Init context
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	//Init storage
	repo, err := postgres.NewRepository(ctx, cfg.DB.Address)
	for i := 1; i <= 10 && err != nil; i++ {
		slog.ErrorContext(logger.ErrorCtx(ctx, err), "Storage no connect", "try", i, slog.Any("error", err))
		select {
		case <-ctx.Done():
			return logger.WrapError(ctx, ctx.Err())
		case <-time.After(time.Second * 2):
		}
		repo, err = postgres.NewRepository(ctx, cfg.DB.Address)
	}
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("connect storage: %w", err))
	}
	defer repo.Close()
	slog.Info("Init storage")

	//Init usecase
	ser := usecase.NewServices(repo)

	//Init grpc server
	lis, err := net.Listen("tcp", cfg.GRPC.AuthAddr)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("listen grpc: %w", err))
	}
	defer lis.Close()

	grpcServer := v1.NewServer(ser)
	slog.Info("Init grpc server")

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("gRPC server started", slog.String("addr", lis.Addr().String()))
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			serverErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		grpcServer.GracefulStop()
	case err := <-serverErr:
		grpcServer.GracefulStop()
		return logger.WrapError(ctx, fmt.Errorf("serve grpc: %w", err))
	}

	return nil
}
