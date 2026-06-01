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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/integration_test/awsmock"
	"github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

// TestPKCEAuthFlow exercises the full PKCE authorization-code authentication flow
// against a local mock HTTP server.  PKCECallbackClient automatically delivers
// the browser redirect callback so the test runs without user interaction.
func TestPKCEAuthFlow(t *testing.T) {
	server := awsmock.NewMockAWSServer()
	defer server.Close()

	// Queue RegisterClient (returns AuthorizationEndpoint so pkceAuthorizationEndpoint()
	// constructs a URL the SDK will build the auth URL from) and CreateToken (the code exchange).
	server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "pkce-client-id",
		ClientSecret:          "pkce-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
		AuthorizationEndpoint: server.URL(),
	})
	server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "pkce-access-token",
		ExpiresIn:    28800,
		RefreshToken: "pkce-refresh-token",
		TokenType:    "Bearer",
	})

	tfile, err := os.CreateTemp("", "*.pkce.integration.json")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	tfile.Close()

	store, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	conf := &ssoconfig.SSOConfig{
		StartUrl:     "https://test.awsapps.com/start",
		SSORegion:    "us-east-1",
		AuthWorkflow: oidc.AuthWorkflowPKCE,
		Accounts:     map[string]*ssoconfig.SSOAccount{},
	}
	conf.SetKey("test-pkce-flow")

	r := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 1
		o.MaxBackoff = 0
	})
	baseOIDCAPI := ssooidc.New(ssooidc.Options{
		Region:       conf.SSORegion,
		Retryer:      r,
		BaseEndpoint: aws.String(server.URL()),
		Credentials:  aws.AnonymousCredentials{},
	})
	baseClient := oidc.NewAWSWithAPI(baseOIDCAPI)
	pkceClient := awsmock.NewPKCECallbackClient(baseClient, "test-pkce-auth-code")

	as := auth.NewAWSSSOForTestWithOIDCClient(conf, store, server.URL(), pkceClient)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = as.Authenticate(ctx, uri.Print, "")
	assert.NoError(t, err)

	// ValidAuthToken reloads the persisted token from the store; confirms it was saved.
	assert.True(t, as.ValidAuthToken(ctx), "token should be valid after PKCE authentication")
}
