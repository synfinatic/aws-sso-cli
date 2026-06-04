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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2ESetupProfilesCmd_Print verifies that SetupProfilesCmd.Run with Print=true succeeds.
// PrintAwsConfig writes to a package-level var (not os.Stdout), so we only assert no error.
func TestE2ESetupProfilesCmd_Print(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Setup.Profiles = SetupProfilesCmd{
		Print: true,
	}

	require.NoError(t, (&SetupProfilesCmd{}).Run(ctx))
}

// TestE2ESetupProfilesCmd_Update verifies that SetupProfilesCmd.Run writes an AWS config file.
func TestE2ESetupProfilesCmd_Update(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	awsConfigPath := filepath.Join(t.TempDir(), "aws-config")

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Setup.Profiles = SetupProfilesCmd{
		Force:     true,
		AwsConfig: awsConfigPath,
	}

	require.NoError(t, (&SetupProfilesCmd{}).Run(ctx))

	data, err := os.ReadFile(awsConfigPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[profile ")
}
