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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/integration_test/awsmock"
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	sso "github.com/synfinatic/aws-sso-cli/internal/sso"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// e2eSetup holds all state for a single e2e test run.
type e2eSetup struct {
	Server   *awsmock.MockAWSServer
	Settings *sso.Settings
	Store    storage.SecureStorage
	SSOConf  *ssoconfig.SSOConfig
	SSOName  string
	TempDir  string
}

// writeTestConfig writes a minimal aws-sso config YAML to tempDir/config.yaml
// and returns the path.  authWorkflow must be "device_code" or "pkce".
func writeTestConfig(t *testing.T, tempDir, serverURL, defaultSSO string,
	extraSSOs map[string]string, authWorkflow string) string {
	t.Helper()

	ssoBlock := fmt.Sprintf("  %s:\n    SSORegion: us-east-1\n    StartUrl: %s\n",
		defaultSSO, serverURL)
	for name, url := range extraSSOs {
		ssoBlock += fmt.Sprintf("  %s:\n    SSORegion: us-west-2\n    StartUrl: %s\n",
			name, url)
	}

	content := fmt.Sprintf(`SSOConfig:
%s
SecureStore: json
JsonStore: %s
DefaultSSO: %s
UrlAction: print
AuthWorkflow: %s
ProfileFormat: "{{.AccountIdPad}}:{{.RoleName}}"
`,
		ssoBlock,
		filepath.Join(tempDir, "store.json"),
		defaultSSO,
		authWorkflow,
	)

	configPath := filepath.Join(tempDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))
	return configPath
}

// newE2ESetup creates a full test environment with a single Default SSO instance
// using the device_code authentication workflow.
func newE2ESetup(t *testing.T) *e2eSetup {
	t.Helper()
	return newE2ESetupWithDefaults(t, "Default", nil, "device_code")
}

// newE2ESetupMultiSSO creates a test environment with Default and Secondary SSO
// instances pointing to the same mock server.  defaultSSO controls which is the
// DefaultSSO in the config file; AwsSSO is pre-set to that instance.
func newE2ESetupMultiSSO(t *testing.T, defaultSSO string) *e2eSetup {
	t.Helper()
	otherSSO := "Secondary"
	if defaultSSO == "Secondary" {
		otherSSO = "Default"
	}
	return newE2ESetupWithDefaults(t, defaultSSO, map[string]string{otherSSO: ""}, "device_code")
}

// newE2ESetupWithDefaults is the shared constructor.  extraSSOs is a map of
// SSO name → StartUrl; an empty string means "use the mock server URL".
// authWorkflow must be "device_code" or "pkce".
func newE2ESetupWithDefaults(
	t *testing.T,
	defaultSSO string,
	extraSSOs map[string]string,
	authWorkflow string,
) *e2eSetup {
	t.Helper()

	tempDir := t.TempDir()
	server := awsmock.NewMockAWSServer()
	t.Cleanup(server.Close)

	// Fill in the server URL for any extras that have an empty StartUrl.
	resolved := make(map[string]string, len(extraSSOs))
	for k, v := range extraSSOs {
		if v == "" {
			v = server.URL()
		}
		resolved[k] = v
	}

	configPath := writeTestConfig(t, tempDir, server.URL(), defaultSSO, resolved, authWorkflow)
	cachePath := filepath.Join(tempDir, "cache.json")

	settings, err := sso.LoadSettings(configPath, cachePath, DEFAULT_CONFIG, sso.OverrideSettings{})
	require.NoError(t, err)

	ctx := context.Background()
	store, err := storage.OpenJsonStore(ctx, filepath.Join(tempDir, "store.json"))
	require.NoError(t, err)

	// Select the default SSO config and create an AwsSSO pointing at the mock.
	ssoConf, err := settings.GetSelectedSSO(defaultSSO)
	require.NoError(t, err)
	ssoName, err := settings.GetSelectedSSOName(defaultSSO)
	require.NoError(t, err)

	AwsSSO = ssoauth.NewAWSSSOForTest(ssoConf, store, server.URL())
	t.Cleanup(func() { AwsSSO = nil })

	return &e2eSetup{
		Server:   server,
		Settings: settings,
		Store:    store,
		SSOConf:  ssoConf,
		SSOName:  ssoName,
		TempDir:  tempDir,
	}
}

// newE2ESetupPKCE is like newE2ESetup but configures AwsSSO for the PKCE
// authorization-code workflow.  A PKCECallbackClient automatically delivers
// the browser redirect so the test runs headlessly.
func newE2ESetupPKCE(t *testing.T) *e2eSetup {
	t.Helper()

	// Use "pkce" so LoadSettings propagates AuthWorkflowPKCE to the SSO config.
	setup := newE2ESetupWithDefaults(t, "Default", nil, "pkce")

	// Build a custom OIDC client that auto-delivers the PKCE callback.
	r := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 1
		o.MaxBackoff = 0
	})
	oidcAPI := ssooidc.New(ssooidc.Options{
		Region:       setup.SSOConf.SSORegion,
		Retryer:      r,
		BaseEndpoint: aws.String(setup.Server.URL()),
		Credentials:  aws.AnonymousCredentials{},
	})
	baseClient := oidc.NewAWSWithAPI(oidcAPI)
	pkceClient := awsmock.NewPKCECallbackClient(baseClient, "test-pkce-auth-code")

	AwsSSO = ssoauth.NewAWSSSOForTestWithOIDCClient(
		setup.SSOConf, setup.Store, setup.Server.URL(), pkceClient,
	)
	return setup
}

// preAuth seeds a valid device-code SSO token into the store so commands that
// call checkAuth / ValidAuthToken see an already-authenticated state and skip
// the OIDC flow entirely.
func preAuth(t *testing.T, setup *e2eSetup) {
	t.Helper()
	ctx := context.Background()
	key := AwsSSO.StoreKey()

	err := setup.Store.SaveRegisterClientData(ctx, key, storage.RegisterClientData{
		ClientId:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientIdIssuedAt:      time.Now().Unix(),
		ClientSecretExpiresAt: time.Now().Add(90 * 24 * time.Hour).Unix(),
		GrantTypes: []storage.GrantType{
			storage.GrantTypeDeviceCode,
			storage.GrantTypeRefreshToken,
		},
	})
	require.NoError(t, err)

	err = setup.Store.SaveCreateTokenResponse(ctx, key, storage.CreateTokenResponse{
		AccessToken: "test-access-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		TokenType:   "Bearer",
	})
	require.NoError(t, err)
}

// populateCache queues ListAccounts + ListAccountRoles mock responses and then
// calls Cache.Refresh so the cache contains a known set of accounts and roles.
// After this call, the Default SSO cache has:
//
//	Account 123456789012 "TestAccount" with roles ReadOnly and PowerUser.
func populateCache(t *testing.T, setup *e2eSetup) {
	t.Helper()

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

	_, _, err := setup.Settings.Cache.Refresh(
		AwsSSO, setup.SSOConf, setup.SSOName, 1, setup.Settings,
	)
	require.NoError(t, err)
	require.NoError(t, setup.Settings.Cache.Save(false))
}

// queueRoleCredentials enqueues a single GetRoleCredentials mock response with
// predictable test credentials.
func queueRoleCredentials(server *awsmock.MockAWSServer) {
	server.SSO.QueueGetRoleCredentials(awsmock.GetRoleCredentialsResponse{
		RoleCredentials: awsmock.RoleCredentials{
			AccessKeyID:     "AKIDTEST12345",
			SecretAccessKey: "SECRETTEST12345",
			SessionToken:    "TOKENTEST12345",
			Expiration:      time.Now().Add(1 * time.Hour).UnixMilli(),
		},
	})
}

// captureStdout runs fn and returns everything written to os.Stdout during fn.
// Stdout is restored even if fn panics.
func captureStdout(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w

	// Run fn inside a closure so defer fires before we read from r.
	func() {
		defer func() {
			w.Close()
			os.Stdout = old
		}()
		fn()
	}()

	buf, _ := io.ReadAll(r)
	r.Close()
	return string(buf)
}

// newRunContext builds a RunContext wired to the given e2eSetup.
func newRunContext(setup *e2eSetup, auth CommandAuth) *RunContext {
	return &RunContext{
		Cli:      &CLI{},
		Settings: setup.Settings,
		Store:    setup.Store,
		Auth:     auth,
		Ctx:      context.Background(),
	}
}
