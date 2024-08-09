package test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"regexp"
	"strings"

	"github.com/davecgh/go-spew/spew"
	lossless "github.com/joeshaw/json-lossless"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
)

// TeslLogger impliments logger.CustomLogger
type TestLogger struct {
	*logger.Logger
	r *io.PipeReader
	w *io.PipeWriter
}

type LogMessages []LogMessage

type LogMessage struct {
	Level         string     `json:"level"`
	Message       string     `json:"msg"`
	Time          string     `json:"time"`
	Source        FileSource `json:"source"`
	lossless.JSON `json:"-"`
}

type FileSource struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line"`
}

func NewTestLogger(level string) *TestLogger {
	reader, writer := io.Pipe()

	l := logger.LevelStrings[strings.ToUpper(level)].Level()

	return &TestLogger{
		Logger: logger.NewLogger(logger.NewJSON, writer, false, l, false),
		r:      reader,
		w:      writer,
	}
}

func (tl *TestLogger) Close() {
	tl.w.Close()
	tl.r.Close()
}

func (tl *TestLogger) GetLast(level slog.Level) (*LogMessage, error) {
	messages := LogMessages{}
	decoder := json.NewDecoder(tl.r)
	if err := decoder.Decode(&messages); err != nil {
		return nil, err
	}
	for i := len(messages) - 1; i >= 0; i-- {
		msg := messages[i]
		if msg.Level == level.String() {
			return &msg, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No %s messages found", level.String()))
}

func (tl *TestLogger) CheckLastEqual(level slog.Level, field, value string) (bool, error) {
	msg, err := tl.GetLast(level)
	if err != nil {
		return false, err
	}

	fmt.Printf("CheckLastEqual decoded msg: %s", spew.Sdump(msg))
	if reflect.ValueOf(msg).FieldByName(field).String() == value {
		return true, nil
	}
	return false, nil
}

func (tl *TestLogger) CheckLastMatch(level slog.Level, field string, match *regexp.Regexp) (bool, error) {
	msg, err := tl.GetLast(level)
	if err != nil {
		return false, err
	}

	fmt.Printf("CheckLastMatch decoded msg: %s", spew.Sdump(msg))
	value := reflect.ValueOf(msg).FieldByName(field).String()
	if match.MatchString(value) {
		return true, nil
	}
	return false, nil
}
