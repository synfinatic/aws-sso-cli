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

// TestDeviceCodeAuthFlow exercises the full OIDC device-code authentication
// flow against a local mock HTTP server.  It verifies that Authenticate()
// exchanges the device code for a token and persists it in the secure store.
func TestDeviceCodeAuthFlow(t *testing.T) {
	server := awsmock.NewMockAWSServer()
	defer server.Close()

	// Queue the three OIDC calls in order: RegisterClient → DeviceAuth → CreateToken.
	server.SSOOIDC.QueueRegisterClient(awsmock.RegisterClientResponse{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientIDIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	server.SSOOIDC.QueueDeviceAuth(awsmock.DeviceAuthResponse{
		DeviceCode:              "test-device-code",
		UserCode:                "TEST-1234",
		VerificationURI:         "https://verify.example.com/activate",
		VerificationURIComplete: "https://verify.example.com/activate?user_code=TEST-1234",
		ExpiresIn:               600,
		Interval:                0,
	})
	server.SSOOIDC.QueueCreateToken(awsmock.OIDCTokenResponse{
		AccessToken:  "test-access-token",
		ExpiresIn:    28800,
		IDToken:      "test-id-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	})

	tfile, err := os.CreateTemp("", "*.integration.json")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())

	store, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	conf := &ssoconfig.SSOConfig{
		StartUrl:     "https://test.awsapps.com/start",
		SSORegion:    "us-east-1",
		AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		Accounts:     map[string]*ssoconfig.SSOAccount{},
	}
	conf.SetKey("test-auth-flow")

	as := auth.NewAWSSSOForTest(conf, store, server.URL())

	ctx := context.Background()
	err = as.Authenticate(ctx, uri.Print, "")
	assert.NoError(t, err)

	// ValidAuthToken loads the persisted token from the store; confirms it was saved.
	assert.True(t, as.ValidAuthToken(ctx), "token should be valid after authentication")
}
