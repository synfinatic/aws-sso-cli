package logger

import "log/slog"

const (
	LineKey     = "_line"
	FileKey     = "_file"
	FunctionKey = "_function"
)

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	// Remove time from the output for predictable test output.
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}

	// Fix level names and pad the names
	/*
		if a.Key == slog.LevelKey {
			level := a.Value.Any().(slog.Level)

			levelLabel, exists := LevelNames[level]
			if !exists {
				levelLabel = level.String()
			}

			// Pad the level name to 8 characters
			a.Value = slog.StringValue(levelLabel) // fmt.Sprintf("%8s", levelLabel))
		}
	*/

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
}
