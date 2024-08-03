package logger

import (
	"io"
	"log/slog"
	"time"

	"github.com/lmittmann/tint"
)

func NewTinc(w io.Writer, addSource bool, level slog.Leveler, color bool) (slog.Handler, *slog.LevelVar) {
	lvl := new(slog.LevelVar)
	lvl.Set(level.Level())

	opts := tint.Options{
		Level:       lvl,
		AddSource:   addSource,
		ReplaceAttr: replaceAttrConsole,
		TimeFormat:  time.Kitchen,
		// TimeFormat: "",
		NoColor: !color,
	}

	return tint.NewHandler(w, &opts), lvl
}
