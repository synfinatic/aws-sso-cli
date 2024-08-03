package logger

import "log/slog"

func replaceAttrConsole(groups []string, a slog.Attr) slog.Attr {
	// Remove time from the output on the console
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}

	// Remove the frame marker attribute flag if it's present
	if a.Key == FrameMarker {
		return slog.Attr{}
	}

	// Colorize and rename the log level
	if a.Key == slog.LevelKey {
		level := a.Value.Any().(slog.Level)
		levelColor, ok := LevelColorsMap[level]
		if ok {
			a.Value = slog.StringValue(levelColor.String(logger.color))
		}
	}

	return a
}

func replaceAttrJson(groups []string, a slog.Attr) slog.Attr {
	// Remove the frame marker attribute flag if it's present
	if a.Key == FrameMarker {
		return slog.Attr{}
	}

	return a
}
