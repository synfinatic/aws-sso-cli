package logger

// Shamelessly stolen from https://betterstack.com/community/guides/logging/logging-in-go/#customizing-slog-handlers

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"

	"github.com/fatih/color"
)

type PrettyHandlerOptions struct {
	*slog.HandlerOptions
	TimeFormat string
	NoColor    bool
}

type PrettyHandler struct {
	slog.Handler
	l          *log.Logger
	TimeFormat string
	NoColor    bool
}

const (
	DefaultTimeFormat = "15:04:05.000"
)

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
	color.NoColor = h.NoColor // disable color if NoColor is set

	level, ok := LevelNames[r.Level]
	if ok {
		level = level + ":"
	} else {
		level = r.Level.String() + ":"
	}

	switch r.Level {
	case LevelTrace:
		level = color.GreenString(level)
	case slog.LevelDebug:
		level = color.MagentaString(level)
	case slog.LevelInfo:
		level = color.BlueString(level)
	case slog.LevelWarn:
		level = color.YellowString(level)
	case slog.LevelError, LevelFatal:
		level = color.RedString(level)
	default:
		level = color.WhiteString(level)
	}

	// figure out the line to generate
	logLine := []any{}
	if h.TimeFormat != "" {
		logLine = append(logLine, r.Time.Format(h.TimeFormat))
	}

	logLine = append(logLine, level, color.CyanString(r.Message))

	fields := make(map[string]interface{}, r.NumAttrs())
	if r.NumAttrs() > 0 {
		r.Attrs(func(a slog.Attr) bool {
			fields[a.Key] = a.Value.Any()
			return true
		})

		b, err := json.MarshalIndent(fields, "", "  ")
		if err != nil {
			return err
		}
		logLine = append(logLine, color.WhiteString(string(b)))
	}

	h.l.Println(logLine...)
	return nil
}

func NewPrettyHandler(out io.Writer, opts PrettyHandlerOptions) *PrettyHandler {
	h := &PrettyHandler{
		Handler:    slog.NewJSONHandler(out, opts.HandlerOptions),
		l:          log.New(out, "", 0),
		TimeFormat: opts.TimeFormat,
		NoColor:    opts.NoColor,
	}

	return h
}
