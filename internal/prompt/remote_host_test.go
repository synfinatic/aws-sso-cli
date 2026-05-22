package prompt

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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UtilsTestSuite struct {
	suite.Suite
}

func unsetEnvWithCleanup(t *testing.T, key string) {
	t.Helper()

	oldValue, hadValue := os.LookupEnv(key)
	t.Cleanup(func() {
		var err error
		if hadValue {
			err = os.Setenv(key, oldValue)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			t.Errorf("failed to restore %s: %v", key, err)
		}
	})

	assert.NoError(t, os.Unsetenv(key))
}

func TestUtilsSuite(t *testing.T) {
	s := &UtilsTestSuite{}
	suite.Run(t, s)
}

func TestIsRemoteHost(t *testing.T) {
	unsetEnvWithCleanup(t, "SSH_TTY")
	unsetEnvWithCleanup(t, "WSL_DISTRO_NAME")
	assert.False(t, IsRemoteHost())

	t.Setenv("SSH_TTY", "FOOBAR")
	assert.True(t, IsRemoteHost())

	assert.NoError(t, os.Unsetenv("SSH_TTY"))
	assert.False(t, IsRemoteHost())

	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	assert.True(t, IsRemoteHost())

	assert.NoError(t, os.Unsetenv("WSL_DISTRO_NAME"))
	assert.False(t, IsRemoteHost())
}
