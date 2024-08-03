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

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	color := isatty.IsTerminal(w.Fd())
	addSource := false
	level := slog.LevelWarn

	logger = NewLogger(CreateLogger, w, addSource, level, color)

	slog.SetDefault(logger.Logger)
}
