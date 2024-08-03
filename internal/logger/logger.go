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
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Our logger which wraps slog.Logger
type Logger struct {
	*slog.Logger
	addSource bool
	color     bool
	level     *slog.LevelVar
	writer    io.Writer
}

// NewLoggerFunc creates a new Logger
func NewLogger(f NewLoggerFunc, w io.Writer, addSource bool, level slog.Leveler, color bool) *Logger {
	handle, lvl := f(w, addSource, level, color)
	return &Logger{
		Logger:    slog.New(handle),
		addSource: addSource,
		color:     color,
		level:     lvl,
		writer:    w,
	}
}

// Copy returns a copy of the Logger current Logger
func (l *Logger) Copy() *Logger {
	return NewLogger(CreateLogger, l.writer, l.addSource, l.level, l.color)
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
	logger = NewLogger(CreateLogger, logger.writer, logger.addSource, logger.level, logger.color)
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

// SetReportCaller sets whether to include the source file and line number in the log output
// Doing so will replace the current logger with a new one that has the new setting
func (l *Logger) SetReportCaller(reportCaller bool) {
	if l.addSource == reportCaller {
		return // do nothing
	}
	l.addSource = reportCaller
	handler, _ := CreateLogger(l.writer, l.addSource, slog.LevelWarn, l.color)
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
