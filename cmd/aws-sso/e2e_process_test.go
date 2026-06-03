//go:build e2etests

package main

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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2EProcess verifies that ProcessCmd.Run outputs valid AWS credential_process
// JSON with the expected fields.
func TestE2EProcess(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Process = ProcessCmd{
		AccountId: 123456789012,
		Role:      "ReadOnly",
	}

	output := captureStdout(func() {
		err := (&ProcessCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	var cpo CredentialProcessOutput
	require.NoError(t, json.Unmarshal([]byte(output), &cpo),
		"process output should be valid JSON")
	assert.Equal(t, 1, cpo.Version)
	assert.Equal(t, "AKIDTEST12345", cpo.AccessKeyId)
	assert.Equal(t, "SECRETTEST12345", cpo.SecretAccessKey)
	assert.Equal(t, "TOKENTEST12345", cpo.SessionToken)
	assert.NotEmpty(t, cpo.Expiration, "Expiration should be set")
}
