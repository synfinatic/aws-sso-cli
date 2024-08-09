package logger

import (
	"io"
	"log/slog"
	"os"

	"github.com/mattn/go-isatty"
)

var logger CustomLogger

type NewLoggerFunc func(w io.Writer, addSource bool, level slog.Leveler, color bool) (slog.Handler, *slog.LevelVar)

// default to the console logger
var CreateLogger NewLoggerFunc = NewJSON // NewConsole

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	color := isatty.IsTerminal(w.Fd())
	addSource := false
	level := slog.LevelWarn

	logger = NewLogger(CreateLogger, w, addSource, level, color)

	slog.SetDefault(logger.GetLogger())
}

func SetLogger(l CustomLogger) {
	logger = l
}

func GetLogger() CustomLogger {
	return logger
}

func SetDefaultLogger(l CustomLogger) {
	slog.SetDefault(l.GetLogger())
}

// SwitchLogger changes the current logger to the specified type
func SwitchLogger(name string) {
	var loggers = map[string]NewLoggerFunc{
		"console": NewConsole,
		"json":    NewJSON,
		"tint":    NewTint,
	}
	var ok bool
	CreateLogger, ok = loggers[name]
	if !ok {
		logger.Fatal("Invalid logger", "name", name)
	}

	// switch the logger
	logger = NewLogger(CreateLogger, logger.Writer(), logger.AddSource(), logger.Level(), logger.Color())
	slog.SetDefault(logger.GetLogger())
}
