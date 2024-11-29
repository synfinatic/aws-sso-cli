package storage

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
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/config"
)

func TestFlockFile(t *testing.T) {
	cfgDir := config.ConfigDir(false)
	assert.Equal(t, fmt.Sprintf("%s/storage.lock", cfgDir), FlockFile(false))

	d, err := os.MkdirTemp("", "test-flockfile")
	assert.NoError(t, err)
	// need to set this here as we're not using the normal location during tests
	flockFile = path.Join(d, "storage.lock")
	assert.Equal(t, fmt.Sprintf("%s/storage.lock", d), FlockFile(false))
}

func TestFlockBlocker(t *testing.T) {
	FlockBlockerReset()
	assert.NoError(t, FlockBlocker())
}
