package logger

import (
	"log/slog"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

func NewTinc(w *os.File, addSource bool, level slog.Leveler) (slog.Handler, *slog.LevelVar) {
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

	return tint.NewHandler(w, &opts), lvl
}
