package logger

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

var logger *Logger

const (
	LevelTrace = slog.Level(-8)
	LevelFatal = slog.Level(12)
)

var LevelNames = map[slog.Leveler]string{
	LevelTrace: "TRACE",
	LevelFatal: "FATAL",
}

var LevelStrings = map[string]slog.Leveler{
	"TRACE": LevelTrace,
	"FATAL": LevelFatal,
	"INFO":  slog.LevelInfo,
	"WARN":  slog.LevelWarn,
	"ERROR": slog.LevelError,
	"DEBUG": slog.LevelDebug,
}

type Logger struct {
	*slog.Logger
	addSource bool
	level     *slog.LevelVar
}

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	logger = NewTincLogger(w, false, slog.LevelWarn)
	// slog.SetDefault(logger.Logger)
}

func NewTincLogger(w *os.File, addSource bool, level slog.Leveler) *Logger {
	lvl := new(slog.LevelVar)
	lvl.Set(level.Level())

	opts := tint.Options{
		Level:       lvl,
		AddSource:   addSource,
		ReplaceAttr: replaceAttr,
		// TimeFormat: time.Kitchen,
		TimeFormat: "",
		LevelColorsMap: tint.LevelColorsMapping{
			LevelTrace:      {Name: "TRACE", Color: color.FgGreen},
			LevelFatal:      {Name: "FATAL", Color: color.FgRed},
			slog.LevelInfo:  {Name: "INFO ", Color: color.FgBlue},
			slog.LevelWarn:  {Name: "WARN ", Color: color.FgYellow},
			slog.LevelError: {Name: "ERROR", Color: color.FgRed},
			slog.LevelDebug: {Name: "DEBUG", Color: color.FgMagenta},
		},
		NoColor: !isatty.IsTerminal(w.Fd()),
	}

	var handle slog.Handler = tint.NewHandler(w, &opts)
	return &Logger{
		Logger:    slog.New(handle),
		addSource: addSource,
		level:     lvl,
	}
}

// SetLevel sets the log level for the logger
func (l *Logger) SetLevel(level slog.Leveler) {
	l.level.Set(level.Level())
}

func (l *Logger) SetLevelString(level string) error {
	if _, ok := LevelStrings[strings.ToUpper(level)]; !ok {
		return fmt.Errorf("invalid log level: %s", level)
	}
	l.level.Set(LevelStrings[strings.ToUpper(level)].Level())
	return nil
}

func (l *Logger) SetReportCaller(reportCaller bool) {
	if l.addSource == reportCaller {
		return // do nothing
	}
	l.addSource = reportCaller
	l.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     l.level,
		AddSource: reportCaller,
	}))
	slog.SetDefault(l.Logger)
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() slog.Leveler {
	return slog.Level(l.level.Level())
}

func SetLogger(l *Logger) {
	logger = l
}

func GetLogger() *Logger {
	return logger
}

func SetDefaultLogger(l *Logger) {
	slog.SetDefault(l.Logger)
}

// Log a message at the Trace level
func (l *Logger) Trace(msg string, args ...interface{}) {
	l.logWithSource(LevelTrace, msg, args...)
}

// Log a message at the Fatal level and exit
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.logWithSource(LevelFatal, msg, args...)
	os.Exit(1)
}

func (l *Logger) logWithSource(level slog.Level, msg string, args ...interface{}) {
	ctx := context.Background()
	var allArgs []interface{}
	allArgs = append(allArgs, args...)

	if l.addSource {
		pc, _, _, ok := runtime.Caller(2) // go up two levels to get the caller
		if ok {
			fs := runtime.CallersFrames([]uintptr{pc})
			f, _ := fs.Next()
			allArgs = append(allArgs, slog.Group("source",
				slog.String("file", f.File), slog.Int("line", f.Line), slog.String("func", f.Function)))
		}
	}
	l.Logger.Log(ctx, level, msg, allArgs...)
}
