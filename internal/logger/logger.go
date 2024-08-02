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
	"strings"
)

var logger *Logger

type Logger struct {
	*slog.Logger
	writer    *os.File
	addSource bool
	level     *slog.LevelVar
}

const (
	LevelTrace = slog.Level(-8)
	LevelFatal = slog.Level(12)
)

var LevelNames = map[slog.Leveler]string{
	LevelTrace: "TRACE",
	LevelFatal: "FATAL",
}

type NewLoggerFunc func(w *os.File, addSource bool, level slog.Leveler) (slog.Handler, *slog.LevelVar)

var NewLogger NewLoggerFunc = NewConsole

var LevelStrings = map[string]slog.Leveler{
	"TRACE": LevelTrace,
	"FATAL": LevelFatal,
	"INFO":  slog.LevelInfo,
	"WARN":  slog.LevelWarn,
	"ERROR": slog.LevelError,
	"DEBUG": slog.LevelDebug,
}

// initialize the default logger to log to stderr and log at the warn level
func init() {
	w := os.Stderr
	addSource := false
	level := slog.LevelWarn
	// logger = NewTincLogger(w, false, slog.LevelWarn)
	handle, lvl := NewLogger(w, addSource, level)

	logger = &Logger{
		Logger:    slog.New(handle),
		writer:    w,
		addSource: addSource,
		level:     lvl,
	}

	slog.SetDefault(logger.Logger)
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
	handler, _ := NewLogger(l.writer, l.addSource, slog.LevelWarn)
	logger.Logger = slog.New(handler)
	slog.SetDefault(logger.Logger)
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

// logWithSource sets the __source attribute so that our Handler knows
// to modify the r.PC value to include the original caller.
func (l *Logger) logWithSource(level slog.Level, msg string, args ...interface{}) {
	ctx := context.Background()
	var allArgs []interface{}
	allArgs = append(allArgs, args...)

	if l.addSource {
		// 5 is the number of stack frames to skip in Handler.Handle()
		allArgs = append(allArgs, slog.Int(FrameMarker, 5))
	}
	l.Logger.Log(ctx, level, msg, allArgs...)
}
