package test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	lossless "github.com/joeshaw/json-lossless"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
)

// TeslLogger impliments logger.CustomLogger
type TestLogger struct {
	*logger.Logger
	r        *io.PipeReader
	w        *io.PipeWriter
	rch      chan []byte
	messages LogMessages
	close    bool
	mutex    sync.Mutex
}

type LogMessages []LogMessage

type LogMessage struct {
	LevelStr      string `json:"level"`
	Level         slog.Level
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

	tl := TestLogger{
		Logger:   logger.NewLogger(logger.NewJSON, writer, false, l, false),
		w:        writer,
		r:        reader,
		messages: LogMessages{},
		close:    false,
		mutex:    sync.Mutex{},
	}

	// start a goroutine to read from the pipe and decode the log messages
	go func() {
		r := bufio.NewReader(tl.r)

		for !tl.close {
			line, err := r.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Fprintf(os.Stderr, "unable to read log message: %s", err.Error())
					break
				}
			}
			msg := LogMessage{}
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				panic(fmt.Sprintf("unable to decode log message: %s", err.Error()))
			}

			tl.mutex.Lock()
			tl.messages = append(tl.messages, msg)
			tl.mutex.Unlock()
		}
	}()

	return &tl
}

func (tl *TestLogger) Close() {
	tl.close = true
	tl.w.Close()
	tl.r.Close()
}

func (tl *TestLogger) ResetBuffer() {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()
	tl.messages = LogMessages{}
}

func (tl *TestLogger) GetLast(msg *LogMessage) error {
	if len(tl.messages) > 0 {
		last := len(tl.messages) - 1
		msg.Level = tl.messages[last].Level
		msg.LevelStr = tl.messages[last].LevelStr
		msg.Message = tl.messages[last].Message
		msg.Time = tl.messages[last].Time
		msg.Source = tl.messages[last].Source
		return nil
	}

	return errors.New("no log messages found")
}

// Returns the last log message of the given level
func (tl *TestLogger) GetLastLevel(level slog.Level, msg *LogMessage) error {
	for i := len(tl.messages) - 1; i >= 0; i-- {
		if tl.messages[i].Level == level {
			msg.Level = tl.messages[i].Level
			msg.LevelStr = tl.messages[i].LevelStr
			msg.Message = tl.messages[i].Message
			msg.Time = tl.messages[i].Time
			msg.Source = tl.messages[i].Source
			return nil
		}
	}

	return fmt.Errorf("no log message found for level %s", level.String())
}

func (tl *TestLogger) CheckLastLevelEqual(level slog.Level, field, value string) (bool, error) {
	msg := LogMessage{}
	err := tl.GetLastLevel(level, &msg)
	if err != nil {
		return false, err
	}

	fmt.Printf("CheckLastLevelEqual decoded msg: %s", spew.Sdump(msg))
	if reflect.ValueOf(msg).FieldByName(field).String() == value {
		return true, nil
	}
	return false, nil
}

func (tl *TestLogger) CheckLastLevelMatch(level slog.Level, field string, match *regexp.Regexp) (bool, error) {
	msg := LogMessage{}
	err := tl.GetLastLevel(level, &msg)
	if err != nil {
		return false, err
	}

	fmt.Printf("CheckLastLevelMatch decoded msg: %s", spew.Sdump(msg))
	value := reflect.ValueOf(msg).FieldByName(field).String()
	if match.MatchString(value) {
		return true, nil
	}
	return false, nil
}

func (tl *TestLogger) CheckLastEqual(field, value string) (bool, error) {
	msg := LogMessage{}
	err := tl.GetLast(&msg)
	if err != nil {
		return false, err
	}

	fmt.Printf("CheckLast decoded msg: %s", spew.Sdump(msg))
	if reflect.ValueOf(msg).FieldByName(field).String() == value {
		return true, nil
	}
	return false, nil
}

func (tl *TestLogger) CheckLastMatch(field string, match *regexp.Regexp) (bool, error) {
	msg := LogMessage{}
	err := tl.GetLast(&msg)
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
