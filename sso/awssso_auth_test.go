package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
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
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
	}

	assert.Equal(t, "atest", as.StoreKey())
}

func TestAuthenticateSteps(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
	}

	as.ssooidc = &mockSsoOidcAPI{
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
	}

	err = as.registerClient(false)
	assert.NoError(t, err)
	assert.Equal(t, "this-is-my-client-id", as.ClientData.ClientId)
	assert.Equal(t, "this-is-my-client-secret", as.ClientData.ClientSecret)
	assert.Equal(t, int64(42), as.ClientData.ClientIdIssuedAt)
	assert.Equal(t, int64(4200), as.ClientData.ClientSecretExpiresAt)

	err = as.startDeviceAuthorization()
	assert.NoError(t, err)
	assert.Equal(t, "device-code", as.DeviceAuth.DeviceCode)
	assert.Equal(t, "user-code", as.DeviceAuth.UserCode)
	assert.Equal(t, "verification-uri", as.DeviceAuth.VerificationUri)
	assert.Equal(t, "verification-uri-complete", as.DeviceAuth.VerificationUriComplete)
	assert.Equal(t, int32(42), as.DeviceAuth.ExpiresIn)
	assert.Equal(t, int32(5), as.DeviceAuth.Interval)

	err = as.createToken()
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

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()

	as.ssooidc = &mockSsoOidcAPI{
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
					ExpiresIn:               int32(expires),
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    int32(expires),
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	}

	err = as.Authenticate("print", "fake-browser")
	assert.NoError(t, err)
	assert.Equal(t, "access-token", as.Token.AccessToken)
	assert.Equal(t, int32(expires), as.Token.ExpiresIn)
	assert.Equal(t, "id-token", as.Token.IdToken)
	assert.Equal(t, "refresh-token", as.Token.RefreshToken)
	assert.Equal(t, "token-type", as.Token.TokenType)

	err = as.Authenticate("", "")
	assert.NoError(t, err)
	assert.Equal(t, "access-token", as.Token.AccessToken)
	assert.Equal(t, int32(expires), as.Token.ExpiresIn)
	assert.Equal(t, "id-token", as.Token.IdToken)
	assert.Equal(t, "refresh-token", as.Token.RefreshToken)
	assert.Equal(t, "token-type", as.Token.TokenType)
}

func TestAuthenticateFailure(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()

	as.ssooidc = &mockSsoOidcAPI{
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
					ExpiresIn:               int32(expires),
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
					ExpiresIn:               int32(expires),
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
					ExpiresIn:               int32(expires),
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
					ExpiresIn:               int32(expires),
					Interval:                5,
				},
				Error: nil,
			},
		},
	}

	err = as.Authenticate("print", "fake-browser")
	assert.Contains(t, err.Error(), "unable to register client with AWS SSO")

	err = as.Authenticate("print", "fake-browser")
	assert.Contains(t, err.Error(), "unable to start device authorization")

	err = as.Authenticate("print", "fake-browser")
	assert.Contains(t, err.Error(), "createToken:")

	err = as.Authenticate("print", "fake-browser")
	assert.Contains(t, err.Error(), "no valid verification url")

	err = as.Authenticate("invalid", "fake-browser")
	assert.Contains(t, err.Error(), "unsupported Open action")

	as.SSOConfig.AuthUrlAction = "invalid"
	err = as.Authenticate("print", "fake-browser")
	assert.Contains(t, err.Error(), "unsupported Open action")
}

func TestReauthenticate(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	as := &AWSSSO{
		SsoRegion:      "us-west-1",
		StartUrl:       "https://testing.awsapps.com/start",
		store:          jstore,
		urlAction:      "invalid",
		browser:        "no-such-browser",
		urlExecCommand: []string{"/dev/null", "%s"},
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
	}

	secs, _ := time.ParseDuration("5s")
	expires := time.Now().Add(secs).Unix()
	/*
		as.ssooidc = &mockSsoOidcAPI{
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
						ExpiresIn:               int32(expires),
						Interval:                5,
					},
					Error: nil,
				},
				{
					CreateToken: &ssooidc.CreateTokenOutput{},
					Error:       fmt.Errorf("some error"),
				},
			},
		}

		// invalid urlAction
		assert.Panics(t, func() { _ = as.reauthenticate() })
	*/
	// valid urlAction, but command is invalid
	as.urlAction = "exec"
	as.ssooidc = &mockSsoOidcAPI{
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
					ExpiresIn:               int32(expires),
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{},
				Error:       fmt.Errorf("some error"),
			},
		},
	}

	err = as.reauthenticate()
	assert.Contains(t, err.Error(), "unable to exec")
}

func TestLogout(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())
	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		key:       "primary",
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		Roles:     map[string][]RoleInfo{},
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
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
				Logout: &sso.LogoutOutput{},
				Error:  nil,
			},
		},
	}

	err = as.Logout()
	assert.NoError(t, err)
	tr := storage.CreateTokenResponse{}
	assert.Error(t, as.store.GetCreateTokenResponse(as.key, &tr))

	as.Token.AccessToken = ""
	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Logout: &sso.LogoutOutput{},
				Error:  nil,
			},
		},
	}

	err = as.Logout()
	assert.Error(t, err)

	err = jstore.SaveCreateTokenResponse("primary", storage.CreateTokenResponse{
		AccessToken:  "access-token",
		ExpiresIn:    42,
		ExpiresAt:    time.Now().Add(duration).Unix(),
		IdToken:      "id-token",
		RefreshToken: "refresh-token",
		TokenType:    "token-type",
	})
	assert.NoError(t, err)
	err = as.Logout()
	assert.NoError(t, err)
	err = jstore.GetCreateTokenResponse("primary", &storage.CreateTokenResponse{})
	assert.Error(t, err)
}
