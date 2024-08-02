package logger

import "log/slog"

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	// Remove time from the output for predictable test output.
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}

	// Remove the frame marker attribute flag if it's present
	if a.Key == FrameMarker {
		return slog.Attr{}
	}

	return a
}
