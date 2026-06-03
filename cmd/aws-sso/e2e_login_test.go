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
