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
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/awsmock"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
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

// TestE2EProcess_WorkflowMismatchKeepsRegistration covers #1521: a device_code
// login (over SSH), then `process` run by something without SSH_TTY, which
// detects pkce.  The registration must survive so the refresh token works
// once the access token expires.
func TestE2EProcess_WorkflowMismatchKeepsRegistration(t *testing.T) {
	setup := newE2ESetupWithDefaults(t, "Default", nil, "pkce", "")
	preAuth(t, setup) // device_code registration with a valid token
	populateCache(t, setup)
	key := AwsSSO.StoreKey()

	ctx := newRunContext(setup, AUTH_REQUIRED)
	require.True(t, checkAuth(ctx), "valid token must be accepted with the other workflow's registration")

	var rcd storage.RegisterClientData
	require.NoError(t, setup.Store.GetRegisterClientData(key, &rcd), "registration must not be deleted")
	assert.Equal(t, "test-client-id", rcd.ClientId)

	// the access token expires; the next process must refresh it silently
	require.NoError(t, setup.Store.SaveCreateTokenResponse(context.Background(), key, storage.CreateTokenResponse{
		AccessToken:  "expired-access-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(),
		RefreshToken: "seeded-refresh-token",
		TokenType:    "Bearer",
	}))
	setup.Server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "refreshed-access-token",
		ExpiresIn:    3600,
		RefreshToken: "rotated-refresh-token",
		TokenType:    "Bearer",
	})
	queueRoleCredentials(setup.Server)

	ctx = newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Process = ProcessCmd{
		AccountId: 123456789012,
		Role:      "ReadOnly",
	}
	require.True(t, checkAuth(ctx), "expired token must be refreshed")
	assert.Equal(t, []string{string(storage.GrantTypeRefreshToken)}, setup.Server.SSOOIDC.TokenGrants())

	output := captureStdout(func() {
		require.NoError(t, (&ProcessCmd{}).Run(ctx))
	})
	var cpo CredentialProcessOutput
	require.NoError(t, json.Unmarshal([]byte(output), &cpo))
	assert.Equal(t, "AKIDTEST12345", cpo.AccessKeyId)

	var ctr storage.CreateTokenResponse
	require.NoError(t, setup.Store.GetCreateTokenResponse(key, &ctr))
	assert.Equal(t, "refreshed-access-token", ctr.AccessToken)
}
