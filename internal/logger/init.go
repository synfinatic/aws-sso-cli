package logger

import (
	"log/slog"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/synfinatic/flexlog"
)

var logger flexlog.FlexLogger
var CreateLogger flexlog.NewLoggerFunc = flexlog.NewConsole

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	color := isatty.IsTerminal(w.Fd())
	addSource := false
	level := slog.LevelWarn

	logger = flexlog.NewLogger(CreateLogger, w, addSource, level, color)

	slog.SetDefault(logger.GetLogger())
}

func SetLogger(l flexlog.FlexLogger) {
	logger = l
}

func GetLogger() flexlog.FlexLogger {
	return logger
}

func SetDefaultLogger(l flexlog.FlexLogger) {
	slog.SetDefault(l.GetLogger())
}

// SwitchLogger changes the current logger to the specified type
func SwitchLogger(name string) {
	var loggers = map[string]flexlog.NewLoggerFunc{
		"console": flexlog.NewConsole,
		"json":    flexlog.NewJSON,
		"tint":    flexlog.NewTint,
	}
	var ok bool
	CreateLogger, ok = loggers[name]
	if !ok {
		logger.Fatal("invalid logger", "name", name)
	}

	// switch the logger
	logger = flexlog.NewLogger(CreateLogger, logger.Writer(), logger.AddSource(), logger.Level(), logger.Color())
	slog.SetDefault(logger.GetLogger())
}
