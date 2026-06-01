//go:build integration

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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/integration_test/awsmock"
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// TestE2ELogin_DeviceCode exercises the full device-code OAuth flow via
// LoginCmd.Run: RegisterClient → DeviceAuth → token poll → cache refresh.
func TestE2ELogin_DeviceCode(t *testing.T) {
	setup := newE2ESetup(t)

	// Queue the OIDC auth flow (Interval=0 means immediate poll, no sleep).
	setup.Server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	setup.Server.SSOOIDC.QueueDeviceAuth(awsmock.DeviceAuthResponse{
		DeviceCode:              "device-code",
		UserCode:                "CODE-1234",
		VerificationURI:         "https://verify.example.com",
		VerificationURIComplete: "https://verify.example.com?user_code=CODE-1234",
		ExpiresIn:               600,
		Interval:                0,
	})
	setup.Server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "test-access-token",
		ExpiresIn:    3600,
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	})

	// Queue the post-auth cache refresh (Login calls Cache.Refresh after auth).
	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "ReadOnly"},
		},
	})

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Login = LoginCmd{UrlAction: "print", Threads: 1}

	// Run login; print action writes verification URL to stderr (not captured).
	cmd := &LoginCmd{}
	err := cmd.Run(ctx)
	require.NoError(t, err)

	// Verify the token was persisted in the store.
	var ctr storage.CreateTokenResponse
	require.NoError(t, setup.Store.GetCreateTokenResponse(AwsSSO.StoreKey(), &ctr))
	assert.Equal(t, "test-access-token", ctr.AccessToken)
	assert.False(t, ctr.Expired(), "token should not be expired after login")
}

// TestE2ELogin_PKCE exercises the PKCE authorization-code flow via LoginCmd.Run.
// PKCECallbackClient auto-delivers the browser redirect so no user interaction is needed.
func TestE2ELogin_PKCE(t *testing.T) {
	setup := newE2ESetupPKCE(t)

	// PKCE uses RegisterClient (with AuthorizationEndpoint) + CreateToken only;
	// there is no DeviceAuth step.
	setup.Server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "pkce-client-id",
		ClientSecret:          "pkce-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
		AuthorizationEndpoint: setup.Server.URL(),
	})
	setup.Server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "pkce-access-token",
		ExpiresIn:    3600,
		RefreshToken: "pkce-refresh-token",
		TokenType:    "Bearer",
	})

	// Queue the post-auth cache refresh.
	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "ReadOnly"},
		},
	})

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Login = LoginCmd{UrlAction: "print", Threads: 1}

	cmd := &LoginCmd{}
	err := cmd.Run(ctx)
	require.NoError(t, err)

	var ctr storage.CreateTokenResponse
	require.NoError(t, setup.Store.GetCreateTokenResponse(AwsSSO.StoreKey(), &ctr))
	assert.Equal(t, "pkce-access-token", ctr.AccessToken)
	assert.False(t, ctr.Expired(), "token should not be expired after PKCE login")
}

// TestE2ECache verifies that CacheCmd.Run fetches accounts/roles from SSO and
// persists them to the local cache file.
func TestE2ECache(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)

	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "ReadOnly"},
			{AccountID: "123456789012", RoleName: "PowerUser"},
		},
	})

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Cache = CacheCmd{Threads: 1, NoConfigCheck: true, Silent: true}

	output := captureStdout(func() {
		err := (&CacheCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	// Verify the cache has the expected accounts and roles.
	ssoCache := setup.Settings.Cache.GetSSO()
	require.NotNil(t, ssoCache.Roles)
	allRoles := ssoCache.Roles.GetAllRoles()
	roleNames := make([]string, 0, len(allRoles))
	for _, r := range allRoles {
		roleNames = append(roleNames, r.RoleName)
	}
	assert.Contains(t, roleNames, "ReadOnly")
	assert.Contains(t, roleNames, "PowerUser")
	_ = output // output goes to stdout but we don't assert on its format
}

// TestE2EList verifies that ListCmd.Run outputs the cached roles to stdout.
func TestE2EList(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId"}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "ReadOnly",
		"list output should contain the cached role name")
	assert.Contains(t, output, "123456789012",
		"list output should contain the account ID")
}

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

// TestE2EEval verifies that EvalCmd.Run outputs shell export statements with
// the AWS credentials for the requested role.
func TestE2EEval(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`,
		"eval output should export the access key ID")
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`,
		"eval output should export the secret access key")
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`,
		"eval output should export the session token")
}

// TestE2EExec verifies that ExecCmd.Run injects credentials into the subprocess
// environment and runs it successfully.
func TestE2EExec(t *testing.T) {
	// checkAwsEnvironment rejects conflicting AWS_ vars; clear them for the test.
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
		if old, ok := os.LookupEnv(v); ok {
			t.Cleanup(func() { os.Setenv(v, old) })
			os.Unsetenv(v)
		}
	}

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
		Cmd:       "/bin/sh",
		Args:      []string{"-c", "exit 0"},
	}

	err := (&ctx.Cli.Exec).Run(ctx)
	assert.NoError(t, err, "exec should run the subprocess without error")
}

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

// TestE2EMultipleSSO_Selection verifies that commands respect both explicit
// --sso flag overrides and the DefaultSSO setting when multiple SSO instances
// are configured.
func TestE2EMultipleSSO_Selection(t *testing.T) {
	t.Run("explicit_sso_flag_overrides_default", func(t *testing.T) {
		// Config has DefaultSSO=Default; we override with --sso Secondary.
		setup := newE2ESetupMultiSSO(t, "Default")

		// Switch AwsSSO to the Secondary instance so API calls go to the right mock.
		secondaryConf, err := setup.Settings.GetSelectedSSO("Secondary")
		require.NoError(t, err)
		AwsSSO = ssoauth.NewAWSSSOForTest(secondaryConf, setup.Store, setup.Server.URL())
		setup.SSOConf = secondaryConf
		setup.SSOName = "Secondary"
		setup.Settings.Cache.SetSSOName("Secondary")

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		t.Setenv("SHELL", "/bin/bash")
		ctx := newRunContext(setup, AUTH_REQUIRED)
		ctx.Cli.SSO = "Secondary"
		ctx.Cli.Eval = EvalCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
		}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "AWS_ACCESS_KEY_ID",
			"eval should succeed using Secondary SSO via --sso flag")

		// Default SSO should have no token — it was never authenticated.
		defaultConf, _ := setup.Settings.GetSelectedSSO("Default")
		defaultKey := ssoauth.NewAWSSSOForTest(defaultConf, setup.Store, setup.Server.URL()).StoreKey()
		var defaultToken storage.CreateTokenResponse
		assert.Error(t, setup.Store.GetCreateTokenResponse(defaultKey, &defaultToken),
			"Default SSO should not have been authenticated")
	})

	t.Run("default_sso_from_config_is_used", func(t *testing.T) {
		// Config has DefaultSSO=Secondary; leave ctx.Cli.SSO empty.
		setup := newE2ESetupMultiSSO(t, "Secondary")
		// newE2ESetupMultiSSO with "Secondary" creates AwsSSO for Secondary already.

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		t.Setenv("SHELL", "/bin/bash")
		ctx := newRunContext(setup, AUTH_REQUIRED)
		// ctx.Cli.SSO is intentionally left empty — DefaultSSO from config applies.
		ctx.Cli.Eval = EvalCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
		}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "AWS_ACCESS_KEY_ID",
			"eval should succeed using Secondary SSO from DefaultSSO config")
		assert.True(t, strings.Contains(output, "AKIDTEST12345"),
			"credentials should come from the Secondary SSO mock")
	})
}
