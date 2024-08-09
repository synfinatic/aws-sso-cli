package logger

import (
	"context"
	"io"
	"log/slog"
)

type CustomLogger interface {
	// slog.Logger methods
	Debug(msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	Enabled(ctx context.Context, level slog.Level) bool
	Error(msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	Handler() slog.Handler
	Info(msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
	LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr)
	Warn(msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	With(args ...any) *slog.Logger
	WithGroup(name string) *slog.Logger
	// custom methods
	Copy() CustomLogger
	// Clone(f NewLoggerFunc, w io.Writer) *CustomLogger
	GetLevel() slog.Leveler
	GetLogger() *slog.Logger
	SetLevel(level slog.Leveler)
	SetLevelString(level string) error
	SetLogger(logger *slog.Logger)
	SetReportCaller(reportCaller bool)
	Trace(msg string, args ...any)
	TraceContext(ctx context.Context, msg string, args ...any)
	Fatal(msg string, args ...any)
	FatalContext(ctx context.Context, msg string, args ...any)
	Writer() io.Writer
	AddSource() bool
	Level() *slog.LevelVar
	Color() bool
}
