package logger

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/flexlog"
	testlogger "github.com/synfinatic/flexlog/test"
)

func TestSetLogger(t *testing.T) {
	l := flexlog.NewLogger(flexlog.NewConsole, os.Stderr, false, slog.LevelWarn, false)
	logger.SetLogger(l.GetLogger())
}

func TestSwitchLogger(t *testing.T) {
	l := flexlog.NewLogger(flexlog.NewConsole, os.Stderr, false, slog.LevelWarn, false)
	logger.SetLogger(l.GetLogger())
	SwitchLogger("json")

	// setup logger for tests
	oldLogger := logger.Copy()
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	logger = tLogger

	defer func() { logger = oldLogger }()

	SwitchLogger("invalid")
	msg := testlogger.LogMessage{}
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, flexlog.LevelFatal, msg.Level)
	assert.Equal(t, "invalid logger", msg.Message)
}
