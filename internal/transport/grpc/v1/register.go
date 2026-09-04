package grpc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Weit145/auth-startup/internal/domain"
	errs "github.com/Weit145/auth-startup/internal/lib/e"
	"github.com/Weit145/auth-startup/internal/logger"
	mapper_err "github.com/Weit145/auth-startup/internal/transport/grpc/v1/err"
	"github.com/Weit145/auth-startup/internal/transport/grpc/v1/mapper"
	"github.com/google/uuid"
	pb "github.com/weit145/proto-startup/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegisterService interface {
	RegisterRequest(ctx context.Context, email string) error
	ConfirmEmail(ctx context.Context, token string, userID uuid.UUID) (domain.AccessToken, error)
	RegisterComplete(ctx context.Context, sessionID uuid.UUID, password string) (domain.User, domain.Tokens, error)
	RepeatEmail(ctx context.Context, email string) error
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.Empty, error) {
	email := req.GetEmail()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "email", Value: &email},
	); err != nil {
		return nil, err
	}

	ctx = logger.WithLogEmail(ctx, email)

	if err := s.ser.RegisterRequest(ctx, email); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)

		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "register request canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "register request` rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "register request failed", slog.Any("error", err))
		}

		return nil, mapper_err.MapErr(err)
	}

	slog.InfoContext(ctx, "register request done")

	return &pb.Empty{}, nil
}

func (s *Server) ConfirmEmail(ctx context.Context, req *pb.ConfirmRequest) (*pb.ConfirmResponse, error) {
	token := req.GetToken()
	userID := req.GetUserID()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "token", Value: &token},
		mapper_err.Field{Name: "userID", Value: &userID},
	); err != nil {
		return nil, err
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		slog.WarnContext(ctx, "invalid userID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid userID")
	}

	ctx = logger.WithLogID(ctx, userUUID)

	accessToken, err := s.ser.ConfirmEmail(ctx, token, userUUID)
	if err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "email confirmed canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "email confirmed rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "email confirmed failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	confirmResp := mapper.MapDomainToConfirmResponse(accessToken)
	slog.InfoContext(ctx, "email confirmed")
	return confirmResp, nil
}

func (s *Server) RegisterComplete(ctx context.Context, req *pb.RegisterCompleteRequest) (*pb.AuthResponse, error) {
	password := req.GetPassword()
	sessionID := req.GetSession()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "password", Value: &password},
		mapper_err.Field{Name: "sessionID", Value: &sessionID},
	); err != nil {
		return nil, err
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		slog.WarnContext(ctx, "invalid sessionID", slog.Any("error", err))
		return nil, status.Error(codes.InvalidArgument, "invalid sessionID")
	}

	ctx = logger.WithLogSessionID(ctx, sessionUUID)

	user, tokens, err := s.ser.RegisterComplete(ctx, sessionUUID, password)
	if err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "register complete canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "register complete rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "register complete failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	authResp := mapper.MapDomainToAuthResponse(user, tokens)
	slog.InfoContext(ctx, "register complete")
	return authResp, nil
}

func (s *Server) RepeatEmail(ctx context.Context, req *pb.Email) (*pb.Empty, error) {
	email := req.GetEmail()

	if err := mapper_err.ValidateInvalidErr(ctx,
		mapper_err.Field{Name: "email", Value: &email},
	); err != nil {
		return nil, err
	}

	ctx = logger.WithLogEmail(ctx, email)

	if err := s.ser.RepeatEmail(ctx, email); err != nil {
		logCtx := logger.ErrorCtx(ctx, err)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			slog.DebugContext(logCtx, "email repeat canceled", slog.Any("error", err))
		case errors.Is(err, errs.ErrInvalidInput),
			errors.Is(err, errs.ErrUnauthorized),
			errors.Is(err, errs.ErrForbidden),
			errors.Is(err, errs.ErrNotFound),
			errors.Is(err, errs.ErrAlreadyExists):
			slog.WarnContext(logCtx, "email repeat rejected", slog.Any("error", err))
		default:
			slog.ErrorContext(logCtx, "email repeat failed", slog.Any("error", err))
		}
		return nil, mapper_err.MapErr(err)
	}

	return &pb.Empty{}, nil
}
