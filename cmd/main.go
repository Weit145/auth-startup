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
	"github.com/Weit145/auth-startup/internal/event"
	tokenInfrastructure "github.com/Weit145/auth-startup/internal/infrastructure/token"
	"github.com/Weit145/auth-startup/internal/logger"
	"github.com/Weit145/auth-startup/internal/repositories/storage/postgres"
	v1 "github.com/Weit145/auth-startup/internal/transport/grpc/v1"
	kafkaTransport "github.com/Weit145/auth-startup/internal/transport/kafka"
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
	cfg, err := config.InitConfig()
	if err != nil {
		return err
	}

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
		return logger.WrapError(ctx, fmt.Errorf("Connect storage: %w", err))
	}
	defer repo.Close()
	slog.Info("Init storage")

	//Init kafka
	kafkaProducer := kafkaTransport.NewProducer(cfg.Kafka.Brokers, cfg.Kafka.NotificationsTopic)
	defer func() {
		if err := kafkaProducer.Close(); err != nil {
			slog.ErrorContext(logger.ErrorCtx(ctx, err), "close kafka producer", slog.Any("error", err))
		}
	}()

	//Init worker publisher
	eventPool, err := event.NewWorkerPool(cfg.Worker.Num, kafkaProducer, repo)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("init worker: %w", err))
	}
	eventPool.Run(ctx)
	slog.Info("Init workers", "count", cfg.Worker.Num)

	//Init infrastructure
	slog.Info("Init infrastructure")
	tokenProvider := tokenInfrastructure.NewProvider(tokenInfrastructure.Settings{
		PrivateKey:      cfg.JWT.PrivateKey,
		RefreshSecret:   cfg.JWT.RefreshSecret,
		AccessTokenTTL:  cfg.Time.AccessTokenTTL,
		ShortSessionTTL: cfg.Time.ShortSessionTTL,
	})

	//Init usecase
	usecaseSettings := usecase.Settings{
		EmailVerificationURL:      cfg.Notification.EmailVerificationURL,
		RefreshTokenTTL:           cfg.Time.RefreshTokenTTL,
		ShortSessionTTL:           cfg.Time.ShortSessionTTL,
		EmailVerificationTokenTTL: cfg.Time.EmailVerificationTokenTTL,
	}
	ser := usecase.NewServices(repo, tokenProvider, usecaseSettings, eventPool)

	//Init grpc server
	lis, err := net.Listen("tcp", cfg.GRPC.AuthAddr)
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("listen grpc: %w", err))
	}
	defer lis.Close()

	grpcServer, err := v1.NewServer(ser, v1.Setting{
		TLSCertPEM:     cfg.GRPC.TLSCertPEM,
		TLSKeyPEM:      cfg.GRPC.TLSKeyPEM,
		TLSClientCAPEM: cfg.GRPC.TLSClientCAPEM,
	})
	if err != nil {
		return logger.WrapError(ctx, fmt.Errorf("create gRPC server: %w", err))
	}
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
