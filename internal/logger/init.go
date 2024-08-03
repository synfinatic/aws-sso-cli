package logger

import (
	"io"
	"log/slog"
	"os"

	"github.com/mattn/go-isatty"
)

var logger *Logger

type NewLoggerFunc func(w io.Writer, addSource bool, level slog.Leveler, color bool) (slog.Handler, *slog.LevelVar)

// default to the console logger
var CreateLogger NewLoggerFunc = NewConsole

func SetLoggerFunc(name string) {
	var loggers = map[string]NewLoggerFunc{
		"console": NewConsole,
		"json":    NewJSON,
		"tint":    NewTinc,
	}
	var ok bool
	CreateLogger, ok = loggers[name]
	if !ok {
		logger.Fatal("Invalid logger", "name", name)
	}
}

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	color := isatty.IsTerminal(w.Fd())
	addSource := false
	level := slog.LevelWarn

	logger = NewLogger(CreateLogger, w, addSource, level, color)

	slog.SetDefault(logger.Logger)
}
