package auth

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
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

// mock ssooidc
type mockSsoOidcAPI struct {
	Results []mockSsoOidcAPIResults
}

type mockSsoOidcAPIResults struct {
	RegisterClient           *ssooidc.RegisterClientOutput
	StartDeviceAuthorization *ssooidc.StartDeviceAuthorizationOutput
	CreateToken              *ssooidc.CreateTokenOutput
	Error                    error
}

func (m *mockSsoOidcAPI) RegisterClient(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	var x mockSsoOidcAPIResults
	switch {
	case len(m.Results) == 0:
		return &ssooidc.RegisterClientOutput{}, fmt.Errorf("calling mocked RegisterClient too many times")

	case m.Results[0].RegisterClient == nil:
		return &ssooidc.RegisterClientOutput{}, fmt.Errorf("expected RegisterClient, but have: %s", spew.Sdump(m.Results[0]))

	default:
		x, m.Results = m.Results[0], m.Results[1:]
		return x.RegisterClient, x.Error
	}
}

func (m *mockSsoOidcAPI) StartDeviceAuthorization(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	var x mockSsoOidcAPIResults
	switch {
	case len(m.Results) == 0:
		return &ssooidc.StartDeviceAuthorizationOutput{}, fmt.Errorf("calling mocked StartDeviceAuthorization too many times")

	case m.Results[0].StartDeviceAuthorization == nil:
		return &ssooidc.StartDeviceAuthorizationOutput{}, fmt.Errorf("expected StartDeviceAuthorization, but have: %s", spew.Sdump(m.Results[0]))

	default:
		x, m.Results = m.Results[0], m.Results[1:]
		return x.StartDeviceAuthorization, x.Error
	}
}

func (m *mockSsoOidcAPI) CreateToken(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	var x mockSsoOidcAPIResults
	switch {
	case len(m.Results) == 0:
		return &ssooidc.CreateTokenOutput{}, fmt.Errorf("calling mocked CreateToken too many times")

	case m.Results[0].CreateToken == nil:
		return &ssooidc.CreateTokenOutput{}, fmt.Errorf("expected CreateToken, but have: %s", spew.Sdump(m.Results[0]))

	default:
		x, m.Results = m.Results[0], m.Results[1:]
		return x.CreateToken, x.Error
	}
}

func TestStoreKey(t *testing.T) {
	as := &AWSSSO{
		key:       "atest",
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		SSOConfig: &ssoconfig.SSOConfig{},
	}

	assert.Equal(t, "atest", as.StoreKey())
}

func TestAuthWorkflowSelection(t *testing.T) {
	assert.NoError(t, os.Unsetenv("WSL_DISTRO_NAME"))
	assert.NoError(t, os.Unsetenv("SSH_TTY"))

	as := &AWSSSO{}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowPKCE)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeAuthorizationCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken})

	as.SSOConfig = &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowDeviceCode}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowDeviceCode)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeDeviceCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken})

	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")

	as = &AWSSSO{}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowDeviceCode)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeDeviceCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken})

	as.SSOConfig = &ssoconfig.SSOConfig{}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowDeviceCode)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeDeviceCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken})

	as.SSOConfig = &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowPKCE)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeAuthorizationCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken})

	assert.NoError(t, os.Unsetenv("WSL_DISTRO_NAME"))
	t.Setenv("SSH_TTY", "/dev/pts/1")

	as = &AWSSSO{}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowDeviceCode)
	assert.Equal(t, as.authGrantTypes(), []string{string(storage.GrantTypeDeviceCode), string(storage.GrantTypeRefreshToken)})
	assert.Equal(t, as.GrantTypes(), []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken})

	as.SSOConfig = &ssoconfig.SSOConfig{}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowDeviceCode)

	as.SSOConfig = &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE}
	assert.Equal(t, as.getAuthWorkflow(), oidc.AuthWorkflowPKCE)
}

func TestAuthenticateSteps(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &ssoconfig.SSOConfig{
			AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		},
	}

	as.oidcClient = oidc.NewAWSWithAPI(&mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      int64(42),
					ClientSecretExpiresAt: int64(4200),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               42,
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    42,
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	})

	err = as.registerClient(context.Background(), false)
	assert.NoError(t, err)
	assert.Equal(t, "this-is-my-client-id", as.ClientData.ClientId)
	assert.Equal(t, "this-is-my-client-secret", as.ClientData.ClientSecret)
	assert.Equal(t, int64(42), as.ClientData.ClientIdIssuedAt)
	assert.Equal(t, int64(4200), as.ClientData.ClientSecretExpiresAt)

	err = as.startDeviceAuthorization(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "device-code", as.DeviceAuth.DeviceCode)
	assert.Equal(t, "user-code", as.DeviceAuth.UserCode)
	assert.Equal(t, "verification-uri", as.DeviceAuth.VerificationUri)
	assert.Equal(t, "verification-uri-complete", as.DeviceAuth.VerificationUriComplete)
	assert.Equal(t, int32(42), as.DeviceAuth.ExpiresIn)
	assert.Equal(t, int32(5), as.DeviceAuth.Interval)

	err = as.createToken(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "access-token", as.Token.AccessToken)
	assert.Equal(t, int32(42), as.Token.ExpiresIn)
	assert.Equal(t, "id-token", as.Token.IdToken)
	assert.Equal(t, "refresh-token", as.Token.RefreshToken)
	assert.Equal(t, "token-type", as.Token.TokenType)
}

func TestAuthenticate(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &ssoconfig.SSOConfig{
			AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()

	as.oidcClient = oidc.NewAWSWithAPI(&mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    int32(expires), // #nosec
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},

			// UrlAction = invalid
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    int32(expires), // #nosec
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},

			// UrlAction = exec
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    int32(expires), // #nosec
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	})

	as.ValidAuthToken(context.Background())
	assert.False(t, as.ValidAuthToken(context.Background()))

	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.NoError(t, err)
	assert.True(t, as.ValidAuthToken(context.Background()))
	assert.Equal(t, "access-token", as.Token.AccessToken)
	assert.Equal(t, int32(expires), as.Token.ExpiresIn) // #nosec
	assert.Equal(t, "id-token", as.Token.IdToken)
	assert.Equal(t, "refresh-token", as.Token.RefreshToken)
	assert.Equal(t, "token-type", as.Token.TokenType)

	// We should now have a valid auth token
	assert.True(t, as.ValidAuthToken(context.Background()))
	assert.Equal(t, "access-token", as.Token.AccessToken)
	assert.Equal(t, int32(expires), as.Token.ExpiresIn) // #nosec
	assert.Equal(t, "id-token", as.Token.IdToken)
	assert.Equal(t, "refresh-token", as.Token.RefreshToken)
	assert.Equal(t, "token-type", as.Token.TokenType)

	// verify CLI override
	as.SSOConfig.AuthUrlAction = "invalid"
	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.NoError(t, err)

	// verify no override of CLI when not set
	err = as.Authenticate(context.Background(), uri.Print, "fake-browser")
	assert.NoError(t, err)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("code did not panic as expected: %v", r)
		}
	}()

	// we can't exec with bad config
	as.SSOConfig.AuthUrlAction = uri.Exec
	_ = as.Authenticate(context.Background(), uri.Undef, "fake-browser")
}

func authTokenSetup(t *testing.T, workflow oidc.AuthWorkflow) (as *AWSSSO, key string, jstore storage.SecureStorage) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err = storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = os.Remove(tfile.Name()) // nolint:gosec
	})

	// Use a mock oidcClient that always fails the refresh so that expired-token
	// test cases correctly return false without panicking on a nil pointer.
	as = &AWSSSO{
		SsoRegion:  "us-west-1",
		StartUrl:   "https://testing.awsapps.com/start",
		store:      jstore,
		oidcClient: &mockOIDCClient{exchangeRefreshErr: fmt.Errorf("test: refresh not available")},
		SSOConfig: &ssoconfig.SSOConfig{
			AuthWorkflow: workflow,
		},
	}

	token := storage.CreateTokenResponse{
		AccessToken:  "access_token",
		ExpiresIn:    0,
		ExpiresAt:    0,
		IdToken:      "id_token",
		RefreshToken: "refresh_token",
		TokenType:    "token_type",
	}
	key = as.StoreKey()
	err = jstore.SaveCreateTokenResponse(context.Background(), key, token)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))

	token.ExpiresAt = 99999
	err = jstore.SaveCreateTokenResponse(context.Background(), key, token)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))

	token.ExpiresIn = int32(^int(0) >> 1)
	token.ExpiresAt = 99999999999
	err = jstore.SaveCreateTokenResponse(context.Background(), key, token)
	assert.NoError(t, err)
	return as, key, jstore
}

func TestValidAuthTokenPKCE(t *testing.T) { // nolint:dupl
	var err error
	as, key, jstore := authTokenSetup(t, oidc.AuthWorkflowPKCE)

	// ValidAuthToken requires a stored RegisterClientData with both
	// authorization_code and refresh_token grant type support.
	clientData := storage.RegisterClientData{
		ClientId:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientSecretExpiresAt: 99999999999,
		GrantTypes:            []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken},
	}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.True(t, as.ValidAuthToken(context.Background()))

	clientData.GrantTypes = []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))

	clientData.GrantTypes = []storage.GrantType{storage.GrantTypeAuthorizationCode}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))
}

func TestValidAuthTokenDeviceCode(t *testing.T) { // nolint:dupl
	var err error
	as, key, jstore := authTokenSetup(t, oidc.AuthWorkflowDeviceCode)

	// ValidAuthToken requires a stored RegisterClientData with both
	// device_code and refresh_token grant type support.
	clientData := storage.RegisterClientData{
		ClientId:              "test-client-id",
		ClientSecret:          "test-client-secret",
		ClientSecretExpiresAt: 99999999999,
		GrantTypes:            []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken},
	}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.True(t, as.ValidAuthToken(context.Background()))

	clientData.GrantTypes = []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))

	clientData.GrantTypes = []storage.GrantType{storage.GrantTypeDeviceCode}
	err = jstore.SaveRegisterClientData(context.Background(), key, clientData)
	assert.NoError(t, err)
	assert.False(t, as.ValidAuthToken(context.Background()))
}

func TestAuthenticateFailure(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &ssoconfig.SSOConfig{
			AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()

	as.oidcClient = oidc.NewAWSWithAPI(&mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			// first test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{},
				Error:          fmt.Errorf("some error"),
			},
			// second test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{},
				Error:                    fmt.Errorf("some error"),
			},
			{ // reauthenticate() retries RegisterClient() after StartDeviceAuthorization failure
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{},
				Error:                    fmt.Errorf("some error"),
			},
			// third test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{},
				Error:       fmt.Errorf("some error"),
			},
			// fourth test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String(""),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			// fifth test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			// sixth test
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
		},
	})

	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.Contains(t, err.Error(), "unable to register client with AWS SSO")

	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.Contains(t, err.Error(), "unable to start device authorization")

	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.Contains(t, err.Error(), "createToken:")

	err = as.Authenticate(context.Background(), "print", "fake-browser")
	assert.Contains(t, err.Error(), "no valid verification url")

	err = as.Authenticate(context.Background(), "invalid", "fake-browser")
	assert.Contains(t, err.Error(), "unsupported Open action")
}

func TestReauthenticate(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion:      "us-west-1",
		StartUrl:       "https://testing.awsapps.com/start",
		store:          jstore,
		urlAction:      "invalid",
		browser:        "no-such-browser",
		urlExecCommand: []string{"/dev/null", "%s"},
		SSOConfig: &ssoconfig.SSOConfig{
			AuthWorkflow: oidc.AuthWorkflowDeviceCode,
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()

	// valid urlAction, but command is invalid
	as.urlAction = "exec"
	as.oidcClient = oidc.NewAWSWithAPI(&mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      time.Now().Unix(),
					ClientSecretExpiresAt: int64(expires),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               int32(expires), // #nosec
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{},
				Error:       fmt.Errorf("some error"),
			},
		},
	})

	err = as.reauthenticate(context.Background())
	assert.Contains(t, err.Error(), "unable to exec")
}

func TestLogout(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())
	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		key:       "primary",
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		Roles:     map[string][]ssoconfig.RoleInfo{},
		SSOConfig: &ssoconfig.SSOConfig{},
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
		urlAction: "print",
	}

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Logout: &awssso.LogoutOutput{},
				Error:  nil,
			},
		},
	}

	err = as.Logout(context.Background())
	assert.NoError(t, err)
	tr := storage.CreateTokenResponse{}
	assert.Error(t, as.store.GetCreateTokenResponse(as.key, &tr))

	as.Token.AccessToken = ""
	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Logout: &awssso.LogoutOutput{},
				Error:  nil,
			},
		},
	}

	err = as.Logout(context.Background())
	assert.Error(t, err)

	err = jstore.SaveCreateTokenResponse(context.Background(), "primary", storage.CreateTokenResponse{
		AccessToken:  "access-token",
		ExpiresIn:    42,
		ExpiresAt:    time.Now().Add(duration).Unix(),
		IdToken:      "id-token",
		RefreshToken: "refresh-token",
		TokenType:    "token-type",
	})
	assert.NoError(t, err)
	err = as.Logout(context.Background())
	assert.NoError(t, err)
	err = jstore.GetCreateTokenResponse("primary", &storage.CreateTokenResponse{})
	assert.Error(t, err)
}

// mockOIDCClient is a full mock of the oidc.Client interface, used by PKCE tests.
type mockOIDCClient struct {
	registerClientResult  storage.RegisterClientData
	registerClientErr     error
	startDeviceAuthResult storage.StartDeviceAuthData
	startDeviceAuthErr    error
	pollDeviceCodeResult  storage.CreateTokenResponse
	pollDeviceCodeErr     error
	startPKCEFlowResult   oidc.PKCEAuthCodeFlow
	startPKCEFlowErr      error
	waitForCallbackResult oidc.PKCECallback
	waitForCallbackErr    error
	exchangePKCEResult    storage.CreateTokenResponse
	exchangePKCEErr       error
	exchangeRefreshResult storage.CreateTokenResponse
	exchangeRefreshErr    error

	// captured inputs for assertions
	startPKCEFlowInputs   []oidc.StartPKCEAuthCodeInput
	waitForCallbackInputs []oidc.WaitForPKCECallbackInput
	exchangePKCEInputs    []oidc.ExchangePKCEAuthCodeInput
	exchangeRefreshInputs []oidc.ExchangeRefreshTokenInput
	registerClientInputs  []oidc.RegisterClientInput
}

func (m *mockOIDCClient) RegisterClient(_ context.Context, in oidc.RegisterClientInput) (storage.RegisterClientData, error) {
	m.registerClientInputs = append(m.registerClientInputs, in)
	return m.registerClientResult, m.registerClientErr
}

func (m *mockOIDCClient) StartDeviceAuthorization(_ context.Context, _ oidc.StartDeviceAuthorizationInput) (storage.StartDeviceAuthData, error) {
	return m.startDeviceAuthResult, m.startDeviceAuthErr
}

func (m *mockOIDCClient) PollDeviceCodeToken(_ context.Context, _ oidc.PollDeviceCodeTokenInput) (storage.CreateTokenResponse, error) {
	return m.pollDeviceCodeResult, m.pollDeviceCodeErr
}

func (m *mockOIDCClient) StartPKCEAuthCodeFlow(_ context.Context, in oidc.StartPKCEAuthCodeInput) (oidc.PKCEAuthCodeFlow, error) {
	m.startPKCEFlowInputs = append(m.startPKCEFlowInputs, in)
	return m.startPKCEFlowResult, m.startPKCEFlowErr
}

func (m *mockOIDCClient) WaitForPKCECallback(_ context.Context, in oidc.WaitForPKCECallbackInput) (oidc.PKCECallback, error) {
	m.waitForCallbackInputs = append(m.waitForCallbackInputs, in)
	return m.waitForCallbackResult, m.waitForCallbackErr
}

func (m *mockOIDCClient) ExchangePKCEAuthCode(_ context.Context, in oidc.ExchangePKCEAuthCodeInput) (storage.CreateTokenResponse, error) {
	m.exchangePKCEInputs = append(m.exchangePKCEInputs, in)
	return m.exchangePKCEResult, m.exchangePKCEErr
}

func (m *mockOIDCClient) ExchangeRefreshToken(_ context.Context, in oidc.ExchangeRefreshTokenInput) (storage.CreateTokenResponse, error) {
	m.exchangeRefreshInputs = append(m.exchangeRefreshInputs, in)
	return m.exchangeRefreshResult, m.exchangeRefreshErr
}

func TestPkceAuthorizationEndpoint(t *testing.T) {
	t.Run("default from region", func(t *testing.T) {
		as := &AWSSSO{SsoRegion: "us-east-1"}
		assert.Equal(t, "https://oidc.us-east-1.amazonaws.com/authorize", as.pkceAuthorizationEndpoint())
	})

	t.Run("custom endpoint without /authorize", func(t *testing.T) {
		as := &AWSSSO{
			SsoRegion:  "us-east-1",
			ClientData: storage.RegisterClientData{AuthorizationEndpoint: "https://custom.example.com/oauth2"},
		}
		assert.Equal(t, "https://custom.example.com/oauth2/authorize", as.pkceAuthorizationEndpoint())
	})

	t.Run("custom endpoint already has /authorize", func(t *testing.T) {
		as := &AWSSSO{
			SsoRegion:  "us-east-1",
			ClientData: storage.RegisterClientData{AuthorizationEndpoint: "https://custom.example.com/oauth2/authorize"},
		}
		assert.Equal(t, "https://custom.example.com/oauth2/authorize", as.pkceAuthorizationEndpoint())
	})

	t.Run("custom endpoint with trailing slash", func(t *testing.T) {
		as := &AWSSSO{
			SsoRegion:  "us-east-1",
			ClientData: storage.RegisterClientData{AuthorizationEndpoint: "https://custom.example.com/oauth2/"},
		}
		assert.Equal(t, "https://custom.example.com/oauth2/authorize", as.pkceAuthorizationEndpoint())
	})
}

func TestPkceRedirectURIBase(t *testing.T) {
	as := &AWSSSO{}
	assert.Equal(t, "http://127.0.0.1", as.pkceRedirectURIBase())
}

func TestSaveToken(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	as := &AWSSSO{
		key:   "test-key",
		store: jstore,
	}

	token := storage.CreateTokenResponse{
		AccessToken:  "test-access-token",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		IdToken:      "test-id-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
	}

	err = as.saveToken(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, token.AccessToken, as.Token.AccessToken)
	assert.Equal(t, token.IdToken, as.Token.IdToken)

	// confirm it was written to the store
	var got storage.CreateTokenResponse
	err = jstore.GetCreateTokenResponse("test-key", &got)
	assert.NoError(t, err)
	assert.Equal(t, "test-access-token", got.AccessToken)
}

func TestRegisterClientPKCE(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())

	jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
	assert.NoError(t, err)

	mock := &mockOIDCClient{
		registerClientResult: storage.RegisterClientData{ // #nosec G101
			ClientId:              "pkce-client-id",
			ClientSecret:          "pkce-client-secret",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}

	as := &AWSSSO{
		key:        "test",
		SsoRegion:  "us-west-2",
		StartUrl:   "https://d-test.awsapps.com/start",
		ClientName: awsSSOClientName,
		ClientType: awsSSOClientType,
		store:      jstore,
		oidcClient: mock,
		SSOConfig:  &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE},
	}

	err = as.registerClient(context.Background(), true)
	assert.NoError(t, err)
	assert.Equal(t, "pkce-client-id", as.ClientData.ClientId)

	if assert.Len(t, mock.registerClientInputs, 1) {
		in := mock.registerClientInputs[0]
		assert.Equal(t, []string{"sso:account:access"}, in.Scopes)
		assert.Equal(t, []string{"http://127.0.0.1"}, in.RedirectUris)
		assert.Contains(t, in.GrantTypes, string(storage.GrantTypeAuthorizationCode))
	}
}

func TestReauthenticatePKCE(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			startPKCEFlowResult: oidc.PKCEAuthCodeFlow{
				AuthorizationURL: "https://oidc.us-east-1.amazonaws.com/authorize?client_id=cid",
				State:            "test-state",
				CodeVerifier:     "test-verifier",
			},
			waitForCallbackResult: oidc.PKCECallback{Code: "auth-code"},
			exchangePKCEResult: storage.CreateTokenResponse{ // #nosec G101
				AccessToken:  "pkce-access-token",
				ExpiresIn:    3600,
				ExpiresAt:    time.Now().Add(time.Hour).Unix(),
				IdToken:      "pkce-id-token",
				RefreshToken: "pkce-refresh-token",
				TokenType:    "Bearer",
			},
		}

		as := &AWSSSO{
			key:       "test",
			SsoRegion: "us-east-1",
			store:     jstore,
			urlAction: "print",
			ClientData: storage.RegisterClientData{
				ClientId:     "cid",
				ClientSecret: "csecret",
			},
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE},
		}

		err = as.reauthenticatePKCE(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, "pkce-access-token", as.Token.AccessToken)
		assert.Equal(t, "pkce-id-token", as.Token.IdToken)

		// verify the code verifier and code were forwarded to ExchangePKCEAuthCode
		if assert.Len(t, mock.exchangePKCEInputs, 1) {
			in := mock.exchangePKCEInputs[0]
			assert.Equal(t, "cid", in.ClientID)
			assert.Equal(t, "csecret", in.ClientSecret)
			assert.Equal(t, "auth-code", in.Code)
			assert.Equal(t, "test-verifier", in.CodeVerifier)
		}

		// verify state was forwarded to WaitForPKCECallback
		if assert.Len(t, mock.waitForCallbackInputs, 1) {
			assert.Equal(t, "test-state", mock.waitForCallbackInputs[0].ExpectedState)
		}
	})

	t.Run("StartPKCEAuthCodeFlow error", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			startPKCEFlowErr: fmt.Errorf("pkce start failed"),
		}

		as := &AWSSSO{
			key:        "test",
			SsoRegion:  "us-east-1",
			store:      jstore,
			urlAction:  "print",
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE},
		}

		err = as.reauthenticatePKCE(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to start pkce authorization")
		assert.Contains(t, err.Error(), "pkce start failed")
	})

	t.Run("WaitForPKCECallback error", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			startPKCEFlowResult: oidc.PKCEAuthCodeFlow{
				AuthorizationURL: "https://oidc.us-east-1.amazonaws.com/authorize?client_id=cid",
				State:            "test-state",
				CodeVerifier:     "test-verifier",
			},
			waitForCallbackErr: fmt.Errorf("callback timed out"),
		}

		as := &AWSSSO{
			key:        "test",
			SsoRegion:  "us-east-1",
			store:      jstore,
			urlAction:  "print",
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE},
		}

		err = as.reauthenticatePKCE(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to receive pkce callback")
		assert.Contains(t, err.Error(), "callback timed out")
	})

	t.Run("ExchangePKCEAuthCode error", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			startPKCEFlowResult: oidc.PKCEAuthCodeFlow{
				AuthorizationURL: "https://oidc.us-east-1.amazonaws.com/authorize?client_id=cid",
				State:            "test-state",
				CodeVerifier:     "test-verifier",
			},
			waitForCallbackResult: oidc.PKCECallback{Code: "auth-code"},
			exchangePKCEErr:       fmt.Errorf("token exchange failed"),
		}

		as := &AWSSSO{
			key:        "test",
			SsoRegion:  "us-east-1",
			store:      jstore,
			urlAction:  "print",
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{AuthWorkflow: oidc.AuthWorkflowPKCE},
		}

		err = as.reauthenticatePKCE(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to exchange pkce authorization code")
		assert.Contains(t, err.Error(), "token exchange failed")
	})
}

func TestTryRefreshToken(t *testing.T) {
	clientData := storage.RegisterClientData{
		ClientId:              "refresh-client-id",
		ClientSecret:          "refresh-client-secret",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
		GrantTypes:            []storage.GrantType{storage.GrantTypeAuthorizationCode},
	}
	expiredToken := storage.CreateTokenResponse{
		AccessToken:  "old-access-token",
		ExpiresAt:    1, // expired
		RefreshToken: "stored-refresh-token",
	}

	t.Run("success", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		newToken := storage.CreateTokenResponse{
			AccessToken:  "new-access-token",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
		}
		mock := &mockOIDCClient{
			exchangeRefreshResult: newToken,
		}

		as := &AWSSSO{
			key:        "test",
			store:      jstore,
			oidcClient: mock,
		}

		ok := as.tryRefreshToken(context.Background(), expiredToken, clientData)
		assert.True(t, ok)
		assert.Equal(t, "new-access-token", as.Token.AccessToken)
		assert.Equal(t, "new-refresh-token", as.Token.RefreshToken)

		// verify inputs forwarded to ExchangeRefreshToken
		if assert.Len(t, mock.exchangeRefreshInputs, 1) {
			in := mock.exchangeRefreshInputs[0]
			assert.Equal(t, "refresh-client-id", in.ClientID)
			assert.Equal(t, "refresh-client-secret", in.ClientSecret)
			assert.Equal(t, "stored-refresh-token", in.RefreshToken)
		}

		// verify the new token was persisted in the store
		var got storage.CreateTokenResponse
		err = jstore.GetCreateTokenResponse("test", &got)
		assert.NoError(t, err)
		assert.Equal(t, "new-access-token", got.AccessToken)
	})

	t.Run("exchange error falls back", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			exchangeRefreshErr: fmt.Errorf("token expired"),
		}

		as := &AWSSSO{
			key:        "test",
			store:      jstore,
			oidcClient: mock,
		}

		ok := as.tryRefreshToken(context.Background(), expiredToken, clientData)
		assert.False(t, ok)
		// Token in memory should be unchanged (zero value)
		assert.Equal(t, "", as.Token.AccessToken)
	})
}

func TestValidAuthTokenRefresh(t *testing.T) {
	t.Run("expired token with refresh token is silently renewed", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		newToken := storage.CreateTokenResponse{
			AccessToken:  "refreshed-access-token",
			ExpiresIn:    3600,
			ExpiresAt:    time.Now().Add(time.Hour).Unix(),
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
		}
		mock := &mockOIDCClient{
			exchangeRefreshResult: newToken,
		}

		as := &AWSSSO{
			key:        "test-sso",
			store:      jstore,
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{},
		}

		// Save a valid client registration
		clientData := storage.RegisterClientData{
			ClientId:              "cid",
			ClientSecret:          "csecret",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
			GrantTypes:            []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken},
		}
		err = jstore.SaveRegisterClientData(context.Background(), as.StoreKey(), clientData)
		assert.NoError(t, err)

		// Save an expired token that has a refresh token
		expiredToken := storage.CreateTokenResponse{
			AccessToken:  "old-access-token",
			ExpiresAt:    1, // expired
			RefreshToken: "stored-refresh-token",
		}
		err = jstore.SaveCreateTokenResponse(context.Background(), as.StoreKey(), expiredToken)
		assert.NoError(t, err)

		// ValidAuthToken should silently refresh and return true
		assert.True(t, as.ValidAuthToken(context.Background()))
		assert.Equal(t, "refreshed-access-token", as.Token.AccessToken)
		assert.Equal(t, "new-refresh-token", as.Token.RefreshToken)

		// The new token must be persisted so the next call also succeeds
		assert.True(t, as.ValidAuthToken(context.Background()))
		assert.Len(t, mock.exchangeRefreshInputs, 1) // only refreshed once
	})

	t.Run("expired token with refresh token — refresh fails — returns false", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{
			exchangeRefreshErr: fmt.Errorf("invalid_grant"),
		}

		as := &AWSSSO{
			key:        "test-sso",
			store:      jstore,
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{},
		}

		clientData := storage.RegisterClientData{
			ClientId:              "cid",
			ClientSecret:          "csecret",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
			GrantTypes:            []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken},
		}
		err = jstore.SaveRegisterClientData(context.Background(), as.StoreKey(), clientData)
		assert.NoError(t, err)

		expiredToken := storage.CreateTokenResponse{
			AccessToken:  "old-access-token",
			ExpiresAt:    1,
			RefreshToken: "bad-refresh-token",
		}
		err = jstore.SaveCreateTokenResponse(context.Background(), as.StoreKey(), expiredToken)
		assert.NoError(t, err)

		assert.False(t, as.ValidAuthToken(context.Background()))
		assert.Equal(t, "", as.Token.AccessToken)
	})

	t.Run("expired token without refresh token returns false", func(t *testing.T) {
		tfile, err := os.CreateTemp("", "*storage.json")
		assert.NoError(t, err)
		defer os.Remove(tfile.Name())

		jstore, err := storage.OpenJsonStore(context.Background(), tfile.Name())
		assert.NoError(t, err)

		mock := &mockOIDCClient{}

		as := &AWSSSO{
			key:        "test-sso",
			store:      jstore,
			oidcClient: mock,
			SSOConfig:  &ssoconfig.SSOConfig{},
		}

		clientData := storage.RegisterClientData{
			ClientId:              "cid",
			ClientSecret:          "csecret",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
			GrantTypes:            []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken},
		}
		err = jstore.SaveRegisterClientData(context.Background(), as.StoreKey(), clientData)
		assert.NoError(t, err)

		expiredToken := storage.CreateTokenResponse{
			AccessToken:  "old-access-token",
			ExpiresAt:    1,
			RefreshToken: "", // no refresh token
		}
		err = jstore.SaveCreateTokenResponse(context.Background(), as.StoreKey(), expiredToken)
		assert.NoError(t, err)

		assert.False(t, as.ValidAuthToken(context.Background()))
		// ExchangeRefreshToken should never have been called
		assert.Len(t, mock.exchangeRefreshInputs, 0)
	})
}
