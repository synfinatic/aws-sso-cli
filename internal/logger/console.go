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
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/fatih/color"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

const (
	FrameMarker = "__skip_frames"
)

// NewConsole creates a new slog.Handler for the ConsoleHandler, which wraps tint.NewHandler
// with some customizations.
func NewConsole(w *os.File, addSource bool, level slog.Leveler) (slog.Handler, *slog.LevelVar) {
	lvl := new(slog.LevelVar)
	lvl.Set(level.Level())

	opts := tint.Options{
		Level:       lvl,
		AddSource:   addSource,
		ReplaceAttr: replaceAttr,
		TimeFormat:  time.Kitchen,
		// TimeFormat: "",
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

	return NewConsoleHandler(w, &opts), lvl
}

// impliment the slog.Handler interface via the tint.Handler
type ConsoleHandler struct {
	slog.Handler
}

// ConsoleHandler is a slog.Handler that wraps tint.Handler
func NewConsoleHandler(w *os.File, opts *tint.Options) slog.Handler {
	return &ConsoleHandler{
		tint.NewHandler(w, opts),
	}
}

// Handle is a custom wrapper around the tint.Handler.Handle method which fixes up
// the PC value to be the correct caller for the Fatal/Trace methods
func (h *ConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	var fixStack int64 = 0
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == FrameMarker {
			fixStack = a.Value.Int64()
			return false
		}
		return true
	})

	if fixStack > 0 {
		rn := r.Clone()
		rn.PC, _, _, _ = runtime.Caller(int(fixStack))
		return h.Handler.Handle(ctx, rn)
	}
	return h.Handler.Handle(ctx, r)
}
