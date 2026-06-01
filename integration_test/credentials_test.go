//go:build integration

package integration_test

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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/integration_test/awsmock"
	"github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

// TestCredentialFetchWithRoleChain exercises the full pipeline:
//
//  1. OIDC device-code authentication (RegisterClient → DeviceAuth → CreateToken)
//  2. SSO API account and role discovery (ListAccounts → ListAccountRoles)
//  3. Role-chained credential fetch (GetRoleCredentials for the base role, then
//     STS AssumeRole for the target role that chains through it)
func TestCredentialFetchWithRoleChain(t *testing.T) {
	server := awsmock.NewMockAWSServer()
	defer server.Close()

	// — Auth —
	server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	server.SSOOIDC.QueueDeviceAuth(awsmock.DeviceAuthResponse{
		DeviceCode:              "device-code",
		UserCode:                "CODE-1234",
		VerificationURI:         "https://verify.example.com",
		VerificationURIComplete: "https://verify.example.com?user_code=CODE-1234",
		ExpiresIn:               600,
	})
	server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "test-access-token",
		ExpiresIn:    28800,
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	})

	// — Account discovery —
	server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "Test Account", EmailAddress: "admin@example.com"},
		},
	})

	// — Role discovery —
	server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "BaseRole"},
			{AccountID: "123456789012", RoleName: "TargetRole"},
		},
	})

	// — GetRoleCredentials: BaseRole (fetched directly via SSO API) —
	baseExpiry := time.Now().Add(1 * time.Hour).UnixMilli()
	server.SSO.QueueGetRoleCredentials(awsmock.GetRoleCredentialsResponse{
		RoleCredentials: awsmock.RoleCredentials{
			AccessKeyID:     "ASIA-BASE-KEYID",
			SecretAccessKey: "base-secret-key",
			SessionToken:    "base-session-token",
			Expiration:      baseExpiry,
		},
	})

	// — AssumeRole: TargetRole (assumed using BaseRole credentials) —
	targetExpiry := time.Now().Add(1 * time.Hour)
	server.STS.QueueAssumeRole(awsmock.AssumeRoleResult{
		AccessKeyID:     "ASIA-TARGET-KEYID",
		SecretAccessKey: "target-secret-key",
		SessionToken:    "target-session-token",
		Expiration:      targetExpiry,
		RoleARN:         "arn:aws:iam::123456789012:role/TargetRole",
		SessionName:     "BaseRole@123456789012",
	})

	// SSOConfig with role chain: TargetRole is accessed via BaseRole.
	conf := &ssoconfig.SSOConfig{
		StartUrl:     "https://test.awsapps.com/start",
		SSORegion:    "us-east-1",
		AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		Accounts: map[string]*ssoconfig.SSOAccount{
			"123456789012": {
				Roles: map[string]*ssoconfig.SSORole{
					"TargetRole": {
						ARN: "arn:aws:iam::123456789012:role/TargetRole",
						Via: "arn:aws:iam::123456789012:role/BaseRole",
					},
				},
			},
		},
	}
	conf.SetKey("test-credentials")

	tfile, err := os.CreateTemp("", "*.integration.json")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())

	store, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	as := auth.NewAWSSSOForTest(conf, store, server.URL())
	ctx := context.Background()

	// Authenticate to obtain an access token.
	err = as.Authenticate(ctx, uri.Print, "")
	assert.NoError(t, err)

	// List accounts.
	accounts, err := as.GetAccounts()
	assert.NoError(t, err)
	assert.Len(t, accounts, 1)
	assert.Equal(t, "123456789012", accounts[0].AccountId)
	assert.Equal(t, "Test Account", accounts[0].AccountName)

	// List roles for the account.
	roles, err := as.GetRoles(accounts[0])
	assert.NoError(t, err)
	assert.Len(t, roles, 2)

	// Fetch chained credentials for TargetRole.
	// Internally: GetRoleCredentials(BaseRole via SSO) → AssumeRole(TargetRole via STS).
	creds, err := as.GetRoleCredentials(int64(123456789012), "TargetRole")
	assert.NoError(t, err)
	assert.Equal(t, "ASIA-TARGET-KEYID", creds.AccessKeyId)
	assert.Equal(t, "target-secret-key", creds.SecretAccessKey)
	assert.Equal(t, "target-session-token", creds.SessionToken)
	assert.True(t, creds.RoleChaining, "TargetRole should be accessed via role chaining")
}
