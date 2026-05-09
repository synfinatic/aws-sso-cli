package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/stretchr/testify/assert"
)

func TestStartPKCEAuthCodeFlow(t *testing.T) {
	t.Run("success with generated state", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		flow, err := client.StartPKCEAuthCodeFlow(StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
			ClientID:              "client-id",
			RedirectURI:           "http://localhost:12345/callback",
			Scopes:                []string{"openid", "profile", "email"},
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, flow.State)
		assert.NotEmpty(t, flow.CodeVerifier)
		assert.NotEmpty(t, flow.CodeChallenge)
		assert.Equal(t, PKCECodeChallengeMethodS256, flow.CodeChallengeMethod)

		u, err := url.Parse(flow.AuthorizationURL)
		assert.NoError(t, err)
		q := u.Query()
		assert.Equal(t, "code", q.Get("response_type"))
		assert.Equal(t, "client-id", q.Get("client_id"))
		assert.Equal(t, "http://localhost:12345/callback", q.Get("redirect_uri"))
		assert.Equal(t, flow.State, q.Get("state"))
		assert.Equal(t, flow.CodeChallenge, q.Get("code_challenge"))
		assert.Equal(t, PKCECodeChallengeMethodS256, q.Get("code_challenge_method"))
		assert.Equal(t, "openid profile email", q.Get("scope"))
	})

	t.Run("success with provided state", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		flow, err := client.StartPKCEAuthCodeFlow(StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
			ClientID:              "client-id",
			RedirectURI:           "http://localhost:12345/callback",
			State:                 "known-state",
		})

		assert.NoError(t, err)
		assert.Equal(t, "known-state", flow.State)
	})

	t.Run("invalid input", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		_, err := client.StartPKCEAuthCodeFlow(StartPKCEAuthCodeInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorization endpoint is required")

		_, err = client.StartPKCEAuthCodeFlow(StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "://bad-url",
			ClientID:              "client-id",
			RedirectURI:           "http://localhost:12345/callback",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid authorization endpoint")
	})
}

func TestExchangePKCEAuthCode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				{
					AccessToken: aws.String("access-token"),
					ExpiresIn:   30,
				},
			},
		}
		client := NewAWSWithAPI(api)

		out, err := client.ExchangePKCEAuthCode(context.Background(), ExchangePKCEAuthCodeInput{
			ClientID:     "client-id",
			ClientSecret: "secret",
			Code:         "auth-code",
			CodeVerifier: "pkce-verifier",
			RedirectURI:  "http://localhost:12345/callback",
		})

		assert.NoError(t, err)
		assert.Equal(t, "access-token", out.AccessToken)
		if assert.Len(t, api.createTokenInputs, 1) {
			in := api.createTokenInputs[0]
			assert.Equal(t, GrantTypeAuthorizationCode, aws.ToString(in.GrantType))
			assert.Equal(t, "auth-code", aws.ToString(in.Code))
			assert.Equal(t, "pkce-verifier", aws.ToString(in.CodeVerifier))
			assert.Equal(t, "http://localhost:12345/callback", aws.ToString(in.RedirectUri))
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		_, err := client.ExchangePKCEAuthCode(context.Background(), ExchangePKCEAuthCodeInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client id is required")
	})
}

func TestValidatePKCEState(t *testing.T) {
	assert.NoError(t, ValidatePKCEState("abc", "abc"))

	err := ValidatePKCEState("", "abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected state is empty")

	err = ValidatePKCEState("abc", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "returned state is empty")

	err = ValidatePKCEState("abc", "def")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state mismatch")
}
