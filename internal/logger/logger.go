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
	"io"
	"log/slog"
	"strings"
)

// Our logger which wraps slog.Logger and implements CustomLogger
type Logger struct {
	logger    *slog.Logger
	addSource bool
	color     bool
	level     *slog.LevelVar
	writer    io.Writer
}

// NewLoggerFunc creates a new Logger
func NewLogger(f NewLoggerFunc, w io.Writer, addSource bool, level slog.Leveler, color bool) *Logger {
	handle, lvl := f(w, addSource, level, color)
	return &Logger{
		logger:    slog.New(handle),
		addSource: addSource,
		color:     color,
		level:     lvl,
		writer:    w,
	}
}

// Debug logs a message at the debug level
func (l *Logger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// DebugContext logs a message at the debug level with context
func (l *Logger) DebugContext(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

func (l *Logger) ErrorContext(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l *Logger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

func (l *Logger) InfoContext(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

func (l *Logger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	l.logger.Log(ctx, level, msg, args...)
}

func (l *Logger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	l.logger.LogAttrs(ctx, level, msg, attrs...)
}

func (l *Logger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

func (l *Logger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

func (l *Logger) Handler() slog.Handler {
	return l.logger.Handler()
}

func (l *Logger) With(args ...any) *slog.Logger {
	return l.logger.With(args...)
}

func (l *Logger) WithGroup(name string) *slog.Logger {
	return l.logger.WithGroup(name)
}

// Copy returns a copy of the Logger current Logger
func (l *Logger) Copy() CustomLogger {
	return NewLogger(CreateLogger, l.writer, l.addSource, l.level, l.color)
}

func (l *Logger) Writer() io.Writer {
	return l.writer
}

func (l *Logger) AddSource() bool {
	return l.addSource
}

func (l *Logger) Level() *slog.LevelVar {
	return l.level
}

func (l *Logger) Color() bool {
	return l.color
}

func (l *Logger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.logger.Enabled(ctx, level)
}

/*
// Clone returns a clone of the current Logger with a new Logging function
func (l *Logger) Clone(f NewLoggerFunc, w io.Writer) *Logger {
	return NewLogger(f, w, l.addSource, l.level, l.color)
}
*/

func (l *Logger) GetLogger() *slog.Logger {
	return l.logger
}

func (l *Logger) SetLogger(logger *slog.Logger) {
	l.logger = logger
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
	logger.SetLogger(slog.New(handler))
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() slog.Level {
	return slog.Level(l.level.Level())
}
