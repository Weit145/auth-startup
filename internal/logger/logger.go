package logger

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"

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
	id    uuid.UUID
	name  string
	email string
}

func (h *HandlerMiddlware) Handle(ctx context.Context, rec slog.Record) error {
	if c, ok := ctx.Value(key).(*logCtx); ok {
		if c.email != "" {
			rec.Add("email", c.email)
		}
		if c.name != "" {
			rec.Add("name", c.name)
		}
		if c.id != uuid.Nil {
			rec.Add("id", c.id.String())
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

func WithLogEmail(ctx context.Context, email string) context.Context {
	email = strings.TrimSpace(email)

	if len(email) > 5 {
		email = email[:5] + strings.Repeat("*", len(email)-5)
	}
	if c, ok := ctx.Value(key).(*logCtx); ok {
		c.email = email
		return context.WithValue(ctx, key, c)
	}
	return context.WithValue(ctx, key, &logCtx{email: email})
}

func WithLogName(ctx context.Context, name string) context.Context {
	name = strings.TrimSpace(name)
	if c, ok := ctx.Value(key).(*logCtx); ok {
		c.name = name
		return context.WithValue(ctx, key, c)
	}
	return context.WithValue(ctx, key, &logCtx{name: name})
}

func WithLogID(ctx context.Context, id uuid.UUID) context.Context {
	if c, ok := ctx.Value(key).(*logCtx); ok {
		c.id = id
		return context.WithValue(ctx, key, c)
	}
	return context.WithValue(ctx, key, &logCtx{id: id})
}

type errorWithLogCtx struct {
	next error
	ctx  *logCtx
}

func (e *errorWithLogCtx) Error() string {
	return e.next.Error()
}

func (e *errorWithLogCtx) Unwrap() error {
	return e.next
}

func WrapError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	c := &logCtx{}
	if x, ok := ctx.Value(key).(*logCtx); ok {
		c = x
	}
	return &errorWithLogCtx{
		next: err,
		ctx:  c,
	}
}

func ErrorCtx(ctx context.Context, err error) context.Context {
	var e *errorWithLogCtx
	if errors.As(err, &e) {
		return context.WithValue(ctx, key, e.ctx)
	}
	return ctx
}

func InitLogging(levelString string) {
	level := slog.LevelInfo
	switch strings.ToUpper(strings.TrimSpace(levelString)) {
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
