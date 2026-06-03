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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2ECredentials verifies that CredentialsCmd.Run writes AWS credentials in
// INI format to the requested output file.
func TestE2ECredentials(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	outFile := setup.TempDir + "/credentials"
	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Credentials = CredentialsCmd{
		Profile: []string{"123456789012:ReadOnly"},
		File:    outFile,
	}

	err := (&ctx.Cli.Credentials).Run(ctx)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "AKIDTEST12345",
		"credentials file should contain the access key ID")
	assert.Contains(t, content, "SECRETTEST12345",
		"credentials file should contain the secret access key")
	assert.Contains(t, content, "TOKENTEST12345",
		"credentials file should contain the session token")
}
