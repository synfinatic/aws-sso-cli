package storage

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jpillora/backoff"
	"github.com/synfinatic/aws-sso-cli/internal/config"
)

const (
	FLOCK_FILE = "%s/storage.lock"
)

func FlockFile(expand bool) string {
	if strings.HasPrefix(flockFile, "%s") {
		return fmt.Sprintf(flockFile, config.ConfigDir(expand))
	} else {
		return flockFile
	}
}

var sleeper = &backoff.Backoff{}
var flockFile string = FLOCK_FILE

func init() {
	sleeper = &backoff.Backoff{
		Min:    10 * time.Millisecond,
		Max:    1 * time.Second,
		Factor: 2,
		Jitter: true,
	}
}

func FlockBlockerReset() {
	sleeper.Reset()
}

// FlockBlocker implements fslock.Blocker with exponential backoff.
func FlockBlocker() error {
	time.Sleep(sleeper.Duration())
	return nil
}

// FlockBlockerWithCtx returns an fslock.Blocker that stops if ctx is cancelled.
// Wrap ctx with context.WithTimeout before calling to enforce a lock-wait deadline.
func FlockBlockerWithCtx(ctx context.Context) func() error {
	return func() error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("storage lock wait cancelled: %w", ctx.Err())
		default:
		}
		time.Sleep(sleeper.Duration())
		return nil
	}
}
