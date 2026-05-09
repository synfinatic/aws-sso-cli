package oidc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
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

func TestStartDeviceAuthorization(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api := &mockOIDCAPI{
			startDeviceAuthOutput: &ssooidc.StartDeviceAuthorizationOutput{
				DeviceCode:              aws.String("dev-code"),
				UserCode:                aws.String("user-code"),
				VerificationUri:         aws.String("https://verify.example.com"),
				VerificationUriComplete: aws.String("https://verify.example.com/full"),
				ExpiresIn:               30,
				Interval:                2,
			},
		}

		client := NewAWSWithAPI(api)
		out, err := client.StartDeviceAuthorization(context.Background(), StartDeviceAuthorizationInput{
			StartURL:     "https://start.example.com",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})

		assert.NoError(t, err)
		if assert.Len(t, api.startDeviceAuthInputs, 1) {
			assert.Equal(t, "https://start.example.com", aws.ToString(api.startDeviceAuthInputs[0].StartUrl))
			assert.Equal(t, "client-id", aws.ToString(api.startDeviceAuthInputs[0].ClientId))
			assert.Equal(t, "client-secret", aws.ToString(api.startDeviceAuthInputs[0].ClientSecret))
		}

		assert.Equal(t, "dev-code", out.DeviceCode)
		assert.Equal(t, "user-code", out.UserCode)
		assert.Equal(t, "https://verify.example.com", out.VerificationUri)
		assert.Equal(t, "https://verify.example.com/full", out.VerificationUriComplete)
		assert.Equal(t, int32(30), out.ExpiresIn)
		assert.Equal(t, int32(2), out.Interval)
	})

	t.Run("error passthrough", func(t *testing.T) {
		api := &mockOIDCAPI{startDeviceAuthErr: errors.New("device auth failed")}
		client := NewAWSWithAPI(api)

		_, err := client.StartDeviceAuthorization(context.Background(), StartDeviceAuthorizationInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device auth failed")
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

func TestPollDeviceCodeToken(t *testing.T) {
	t.Run("authorization pending then success", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				nil,
				{
					AccessToken: aws.String("ok"),
					ExpiresIn:   60,
				},
			},
			createTokenErrors: []error{
				&oidctypes.AuthorizationPendingException{},
				nil,
			},
		}
		client := NewAWSWithAPI(api)

		out, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.NoError(t, err)
		assert.Equal(t, "ok", out.AccessToken)
		assert.Len(t, api.createTokenInputs, 2)
	})

	t.Run("slow down then success", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				nil,
				{
					AccessToken: aws.String("ok2"),
					ExpiresIn:   60,
				},
			},
			createTokenErrors: []error{
				&oidctypes.SlowDownException{},
				nil,
			},
		}
		client := NewAWSWithAPI(api)

		out, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.NoError(t, err)
		assert.Equal(t, "ok2", out.AccessToken)
		assert.Len(t, api.createTokenInputs, 2)
	})

	t.Run("unexpected error wrapped", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenErrors: []error{errors.New("bad-token")},
		}
		client := NewAWSWithAPI(api)

		_, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "createToken:")
		assert.Contains(t, err.Error(), "bad-token")
	})

	t.Run("context canceled while waiting", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenErrors: []error{&oidctypes.AuthorizationPendingException{}},
		}
		client := NewAWSWithAPI(api)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := client.PollDeviceCodeToken(ctx, PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			// Leave interval values at zero to exercise defaulting without incurring delay.
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled), fmt.Sprintf("expected context canceled, got: %v", err))
		assert.Len(t, api.createTokenInputs, 1)
	})
}
