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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/awsmock"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// TestE2EFIPSEval_NonChained verifies that AWS_USE_FIPS_ENDPOINT does not break
// the normal (non-chained) eval pipeline. The SSO credential fetch uses the mock
// server via BaseEndpoint and is not subject to FIPS endpoint selection, so the
// command must succeed end-to-end.
func TestE2EFIPSEval_NonChained(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
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

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`)
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`)
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`)
}

// TestE2EFIPSGetRoleCredentials_ViaChain proves that AWS_USE_FIPS_ENDPOINT is
// wired through to the STS client used for role chaining. The AWS SDK rejects
// the combination of UseFIPSEndpoint and a custom BaseEndpoint (used by the mock
// server), producing an error that contains "FIPS". If the flag were absent the
// AssumeRole call would succeed — as shown by TestE2EEval_RoleChain.
//
// AwsSSO.GetRoleCredentials is called directly (not via the cmd-layer wrapper)
// because the wrapper calls log.Fatal on error, which would kill the test process.
func TestE2EFIPSGetRoleCredentials_ViaChain(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	setup := newE2ESetupRoleChain(t)
	preAuth(t, setup)

	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "BaseRole"},
			{AccountID: "123456789012", RoleName: "TargetRole"},
		},
	})
	_, _, err := setup.Settings.Cache.Refresh(AwsSSO, setup.SSOConf, setup.SSOName, 1, setup.Settings)
	require.NoError(t, err)
	require.NoError(t, setup.Settings.Cache.Save(false))

	// BaseRole is fetched from SSO directly (no Via). TargetRole then attempts
	// STS AssumeRole, which fails because FIPS + custom BaseEndpoint are mutually
	// exclusive in the AWS SDK — proving UseFIPSEndpoint was applied.
	setup.Server.SSO.QueueGetRoleCredentials(awsmock.GetRoleCredentialsResponse{
		RoleCredentials: awsmock.RoleCredentials{
			AccessKeyID:     "AKID-BASE",
			SecretAccessKey: "SECRET-BASE",
			SessionToken:    "TOKEN-BASE",
			Expiration:      time.Now().Add(1 * time.Hour).UnixMilli(),
		},
	})

	_, err = AwsSSO.GetRoleCredentials(int64(123456789012), "TargetRole")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FIPS",
		"error must mention FIPS, confirming UseFIPSEndpoint was set on the STS client")
}

// TestE2EFIPSLogin_DeviceCode verifies that the device-code login flow completes
// normally when AWS_USE_FIPS_ENDPOINT is set. The OIDC API calls are routed to
// the mock server via BaseEndpoint and are unaffected by FIPS endpoint selection.
func TestE2EFIPSLogin_DeviceCode(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

	setup := newE2ESetup(t)

	setup.Server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "fips-client-id",
		ClientSecret:          "fips-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	setup.Server.SSOOIDC.QueueDeviceAuth(awsmock.DeviceAuthResponse{
		DeviceCode:              "fips-device-code",
		UserCode:                "FIPS-CODE",
		VerificationURI:         "https://verify.example.com",
		VerificationURIComplete: "https://verify.example.com?user_code=FIPS-CODE",
		ExpiresIn:               600,
		Interval:                0,
	})
	setup.Server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "fips-access-token",
		ExpiresIn:    3600,
		RefreshToken: "fips-refresh-token",
		TokenType:    "Bearer",
	})
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
	require.NoError(t, err, "device-code login must succeed with AWS_USE_FIPS_ENDPOINT set")

	var ctr storage.CreateTokenResponse
	require.NoError(t, setup.Store.GetCreateTokenResponse(AwsSSO.StoreKey(), &ctr))
	assert.Equal(t, "fips-access-token", ctr.AccessToken)
	assert.False(t, ctr.Expired(), "token should not be expired after login")
}
