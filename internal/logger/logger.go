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
)

var logger *Logger

const (
	LevelTrace  = slog.Level(-8)
	LevelFatal  = slog.Level(12)
	LineKey     = "_line"
	FileKey     = "_file"
	FunctionKey = "_function"
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
	logger = NewLogger(true, slog.LevelWarn)
	slog.SetDefault(logger.Logger)
}

// NewLogger creates a new logger with the given log level and whether to add source information
func NewLogger(addSource bool, level slog.Leveler) *Logger {
	lvl := new(slog.LevelVar)
	lvl.Set(level.Level())

	opts := PrettyHandlerOptions{
		TimeFormat: "",
		HandlerOptions: &slog.HandlerOptions{
			AddSource: addSource,
			Level:     lvl,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time from the output for predictable test output.
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}

				// Fix level names and pad the names
				if a.Key == slog.LevelKey {
					level := a.Value.Any().(slog.Level)

					levelLabel, exists := LevelNames[level]
					if !exists {
						levelLabel = level.String()
					}

					// Pad the level name to 8 characters
					a.Value = slog.StringValue(levelLabel) // fmt.Sprintf("%8s", levelLabel))
				}

				// Rename the source attributes if they came from Trace/Fatal to the correct names
				// so the old values get overwritten
				if len(groups) > 0 && groups[0] == "source" {
					switch a.Key {
					case FileKey:
						a.Key = "file"
					case LineKey:
						a.Key = "line"
					case FunctionKey:
						a.Key = "function"
					default:
						break // do nothing
					}
				}

				return a
			},
		},
	}

	// var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	var handler slog.Handler = NewPrettyHandler(os.Stderr, opts)
	return &Logger{
		Logger:    slog.New(handler),
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
		var functionName string = ""
		pc, file, line, ok := runtime.Caller(2) // go up two levels to get the caller
		if ok {
			functionName = runtime.FuncForPC(pc).Name()
			allArgs = append(allArgs, slog.Group("source", slog.String(FileKey, file), slog.Int(LineKey, line), slog.String(FunctionKey, functionName)))
		}
	}
	l.Logger.Log(ctx, level, msg, allArgs...)
}
