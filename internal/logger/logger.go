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
	"github.com/sirupsen/logrus"
)

var log *Logger

type Logger struct {
	*logrus.Logger
}

func NewLogger(l *logrus.Logger) *Logger {
	return &Logger{l}
}

func init() {
	log = &Logger{logrus.New()}
	log.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	})
}

func SetLogger(l *Logger) {
	log = l
}

func GetLogger() *Logger {
	return log
}
