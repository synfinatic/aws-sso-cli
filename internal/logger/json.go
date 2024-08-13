package logger

import (
	"context"
	"io"
	"log/slog"
	"runtime"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	slogjson "github.com/veqryn/slog-json"
)

func NewJSON(w io.Writer, addSource bool, level slog.Leveler, _ bool) (slog.Handler, *slog.LevelVar) {
	lvl := new(slog.LevelVar)
	lvl.Set(level.Level())

	opts := slogjson.HandlerOptions{
		Level:       lvl,
		AddSource:   addSource,
		ReplaceAttr: replaceAttrJson,
		JSONOptions: json.JoinOptions(
			// Options from the json v2 library (these are the defaults)
			json.Deterministic(true),
			jsontext.AllowDuplicateNames(true),
			jsontext.AllowInvalidUTF8(true),
			jsontext.EscapeForJS(true),
			jsontext.SpaceAfterColon(false),
			jsontext.SpaceAfterComma(true),
		),
	}

	return NewJSONHandler(w, &opts), lvl
}

type JsonHandler struct {
	slog.Handler
}

func NewJSONHandler(w io.Writer, opts *slogjson.HandlerOptions) slog.Handler {
	return &JsonHandler{
		slogjson.NewHandler(w, opts),
	}
}

// Handle is a custom wrapper around the slogjson.Handler.Handle method which fixes up
// the PC value to be the correct caller for the Fatal/Trace methods
func (h *JsonHandler) Handle(ctx context.Context, r slog.Record) error {
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

func replaceAttrJson(groups []string, a slog.Attr) slog.Attr {
	// Remove the frame marker attribute flag if it's present
	if a.Key == FrameMarker {
		return slog.Attr{}
	}

	// Rename the log level
	if a.Key == slog.LevelKey {
		level := a.Value.Any().(slog.Level)
		levelColor, ok := LevelColorsMap[level]
		if ok {
			a.Value = slog.StringValue(levelColor.String(false))
		}
	}

	return a
}
