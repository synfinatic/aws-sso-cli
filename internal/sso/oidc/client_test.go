package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/stretchr/testify/assert"
)

type mockOIDCAPI struct {
	registerClientInputs []*ssooidc.RegisterClientInput
	registerClientOutput *ssooidc.RegisterClientOutput
	registerClientErr    error

	startDeviceAuthInputs []*ssooidc.StartDeviceAuthorizationInput
	startDeviceAuthOutput *ssooidc.StartDeviceAuthorizationOutput
	startDeviceAuthErr    error

	createTokenInputs  []*ssooidc.CreateTokenInput
	createTokenOutputs []*ssooidc.CreateTokenOutput
	createTokenErrors  []error
}

func (m *mockOIDCAPI) RegisterClient(_ context.Context, in *ssooidc.RegisterClientInput, _ ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	m.registerClientInputs = append(m.registerClientInputs, in)
	if m.registerClientOutput == nil {
		return &ssooidc.RegisterClientOutput{}, m.registerClientErr
	}
	return m.registerClientOutput, m.registerClientErr
}

func (m *mockOIDCAPI) StartDeviceAuthorization(_ context.Context, in *ssooidc.StartDeviceAuthorizationInput, _ ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	m.startDeviceAuthInputs = append(m.startDeviceAuthInputs, in)
	if m.startDeviceAuthOutput == nil {
		return &ssooidc.StartDeviceAuthorizationOutput{}, m.startDeviceAuthErr
	}
	return m.startDeviceAuthOutput, m.startDeviceAuthErr
}

func (m *mockOIDCAPI) CreateToken(_ context.Context, in *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	m.createTokenInputs = append(m.createTokenInputs, in)
	idx := len(m.createTokenInputs) - 1

	out := &ssooidc.CreateTokenOutput{}
	if idx < len(m.createTokenOutputs) && m.createTokenOutputs[idx] != nil {
		out = m.createTokenOutputs[idx]
	}

	var err error
	if idx < len(m.createTokenErrors) {
		err = m.createTokenErrors[idx]
	}

	return out, err
}

func TestRegisterClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api := &mockOIDCAPI{
			registerClientOutput: &ssooidc.RegisterClientOutput{
				AuthorizationEndpoint: aws.String("https://auth.example.com"),
				ClientId:              aws.String("client-id"),
				ClientSecret:          aws.String("client-secret"),
				ClientIdIssuedAt:      100,
				ClientSecretExpiresAt: 200,
				TokenEndpoint:         aws.String("https://token.example.com"),
			},
		}

		client := NewAWSWithAPI(api)
		out, err := client.RegisterClient(context.Background(), RegisterClientInput{
			ClientName: "aws-sso-cli",
			ClientType: "public",
			GrantTypes: []string{"refresh_token"},
			Scopes:     []string{"scope1"},
		})

		assert.NoError(t, err)
		if assert.Len(t, api.registerClientInputs, 1) {
			assert.Equal(t, "aws-sso-cli", aws.ToString(api.registerClientInputs[0].ClientName))
			assert.Equal(t, "public", aws.ToString(api.registerClientInputs[0].ClientType))
			assert.Equal(t, []string{"refresh_token"}, api.registerClientInputs[0].GrantTypes)
			assert.Equal(t, []string{"scope1"}, api.registerClientInputs[0].Scopes)
		}

		assert.Equal(t, "https://auth.example.com", out.AuthorizationEndpoint)
		assert.Equal(t, "client-id", out.ClientId)
		assert.Equal(t, "client-secret", out.ClientSecret)
		assert.Equal(t, int64(100), out.ClientIdIssuedAt)
		assert.Equal(t, int64(200), out.ClientSecretExpiresAt)
		assert.Equal(t, "https://token.example.com", out.TokenEndpoint)
	})

	t.Run("error wrapped", func(t *testing.T) {
		api := &mockOIDCAPI{registerClientErr: errors.New("boom")}
		client := NewAWSWithAPI(api)

		_, err := client.RegisterClient(context.Background(), RegisterClientInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "registerClient:")
		assert.Contains(t, err.Error(), "boom")
	})
}

func TestCreateToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		now := time.Now().Unix()
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				{
					AccessToken:  aws.String("access"),
					ExpiresIn:    42,
					IdToken:      aws.String("id"),
					RefreshToken: aws.String("refresh"),
					TokenType:    aws.String("Bearer"),
				},
			},
		}

		client := NewAWSWithAPI(api)
		out, err := client.CreateToken(context.Background(), CreateTokenInput{
			ClientID:     "cid",
			ClientSecret: "secret",
			GrantType:    "urn:ietf:params:oauth:grant-type:device_code",
			DeviceCode:   "dcode",
			Code:         "auth-code",
			CodeVerifier: "pkce-verifier",
			RedirectURI:  "http://localhost/callback",
		})

		assert.NoError(t, err)
		if assert.Len(t, api.createTokenInputs, 1) {
			in := api.createTokenInputs[0]
			assert.Equal(t, "cid", aws.ToString(in.ClientId))
			assert.Equal(t, "secret", aws.ToString(in.ClientSecret))
			assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", aws.ToString(in.GrantType))
			assert.Equal(t, "dcode", aws.ToString(in.DeviceCode))
			assert.Equal(t, "auth-code", aws.ToString(in.Code))
			assert.Equal(t, "pkce-verifier", aws.ToString(in.CodeVerifier))
			assert.Equal(t, "http://localhost/callback", aws.ToString(in.RedirectUri))
		}

		assert.Equal(t, "access", out.AccessToken)
		assert.Equal(t, int32(42), out.ExpiresIn)
		assert.Equal(t, "id", out.IdToken)
		assert.Equal(t, "refresh", out.RefreshToken)
		assert.Equal(t, "Bearer", out.TokenType)
		assert.GreaterOrEqual(t, out.ExpiresAt, now+41)
		assert.LessOrEqual(t, out.ExpiresAt, now+43)
	})

	t.Run("error passthrough", func(t *testing.T) {
		api := &mockOIDCAPI{createTokenErrors: []error{errors.New("token failed")}}
		client := NewAWSWithAPI(api)

		_, err := client.CreateToken(context.Background(), CreateTokenInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token failed")
	})
}

func TestExchangeRefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		now := time.Now().Unix()
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				{
					AccessToken:  aws.String("new-access"),
					ExpiresIn:    3600,
					IdToken:      aws.String("new-id"),
					RefreshToken: aws.String("new-refresh"),
					TokenType:    aws.String("Bearer"),
				},
			},
		}

		client := NewAWSWithAPI(api)
		out, err := client.ExchangeRefreshToken(context.Background(), ExchangeRefreshTokenInput{
			ClientID:     "cid",
			ClientSecret: "secret",
			RefreshToken: "old-refresh",
		})

		assert.NoError(t, err)
		if assert.Len(t, api.createTokenInputs, 1) {
			in := api.createTokenInputs[0]
			assert.Equal(t, "cid", aws.ToString(in.ClientId))
			assert.Equal(t, "secret", aws.ToString(in.ClientSecret))
			assert.Equal(t, "refresh_token", aws.ToString(in.GrantType))
			assert.Equal(t, "old-refresh", aws.ToString(in.RefreshToken))
			// fields not relevant to refresh token grant should be absent
			assert.Nil(t, in.DeviceCode)
			assert.Nil(t, in.Code)
			assert.Nil(t, in.CodeVerifier)
		}

		assert.Equal(t, "new-access", out.AccessToken)
		assert.Equal(t, int32(3600), out.ExpiresIn)
		assert.Equal(t, "new-id", out.IdToken)
		assert.Equal(t, "new-refresh", out.RefreshToken)
		assert.Equal(t, "Bearer", out.TokenType)
		assert.GreaterOrEqual(t, out.ExpiresAt, now+3599)
	})

	t.Run("missing client id", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		_, err := client.ExchangeRefreshToken(context.Background(), ExchangeRefreshTokenInput{
			RefreshToken: "tok",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client id is required")
	})

	t.Run("missing refresh token", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		_, err := client.ExchangeRefreshToken(context.Background(), ExchangeRefreshTokenInput{
			ClientID: "cid",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token is required")
	})

	t.Run("api error passthrough", func(t *testing.T) {
		api := &mockOIDCAPI{createTokenErrors: []error{errors.New("expired_token")}}
		client := NewAWSWithAPI(api)
		_, err := client.ExchangeRefreshToken(context.Background(), ExchangeRefreshTokenInput{
			ClientID:     "cid",
			RefreshToken: "tok",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired_token")
	})
}
