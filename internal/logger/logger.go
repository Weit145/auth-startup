package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/google/uuid"
)

type HandlerMiddlware struct {
	next slog.Handler
}

func NewHandlerMiddleware(next slog.Handler) *HandlerMiddlware {
	return &HandlerMiddlware{next: next}
}

func (h *HandlerMiddlware) Enabled(ctx context.Context, rec slog.Level) bool {
	return h.next.Enabled(ctx, rec)
}

type keyType int

const key = keyType(0)

type logCtx struct {
	ListID uuid.UUID
}

func (h *HandlerMiddlware) Handle(ctx context.Context, rec slog.Record) error {
	if c, ok := ctx.Value(key).(logCtx); ok {
		if c.ListID != uuid.Nil {
			rec.Add("listID", c.ListID)
		}
	}
	return h.next.Handle(ctx, rec)
}

func (h *HandlerMiddlware) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &HandlerMiddlware{next: h.next.WithAttrs(attrs)}
}

func (h *HandlerMiddlware) WithGroup(name string) slog.Handler {
	return &HandlerMiddlware{next: h.next.WithGroup(name)}
}

func WithLogListID(ctx context.Context, listID uuid.UUID) context.Context {
	if c, ok := ctx.Value(key).(logCtx); ok {
		c.ListID = listID
		return context.WithValue(ctx, key, c)
	}
	return context.WithValue(ctx, key, logCtx{ListID: listID})
}

func InitLogging(levelString string) {
	level := slog.LevelInfo
	switch levelString {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "ERROR":
		level = slog.LevelError
	case "WARN":
		level = slog.LevelWarn
	default:
		level = slog.LevelInfo
	}

	handler := slog.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level, AddSource: false}))
	handler = NewHandlerMiddleware(handler)
	slog.SetDefault(slog.New(handler))
}
