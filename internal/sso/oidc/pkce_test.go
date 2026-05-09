package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

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

func TestWaitForPKCECallback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		redirectURI := testPKCERedirectURI(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resultCh := make(chan PKCECallback, 1)
		errCh := make(chan error, 1)
		go func() {
			callback, err := client.WaitForPKCECallback(ctx, WaitForPKCECallbackInput{
				RedirectURI:   redirectURI,
				ExpectedState: "expected-state",
			})
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- callback
		}()

		waitForPKCEListener(t, redirectURI)

		resp, err := http.Get(fmt.Sprintf("%s?code=auth-code&state=expected-state", redirectURI))
		assert.NoError(t, err)
		if resp != nil {
			_ = resp.Body.Close()
		}

		select {
		case callback := <-resultCh:
			assert.Equal(t, "auth-code", callback.Code)
		case err := <-errCh:
			assert.NoError(t, err)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for PKCE callback: %v", ctx.Err())
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		redirectURI := testPKCERedirectURI(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			_, err := client.WaitForPKCECallback(ctx, WaitForPKCECallbackInput{
				RedirectURI:   redirectURI,
				ExpectedState: "expected-state",
			})
			errCh <- err
		}()

		waitForPKCEListener(t, redirectURI)

		resp, err := http.Get(fmt.Sprintf("%s?code=auth-code&state=wrong-state", redirectURI))
		assert.NoError(t, err)
		if resp != nil {
			_ = resp.Body.Close()
		}

		select {
		case err := <-errCh:
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "state mismatch")
		case <-ctx.Done():
			t.Fatalf("timed out waiting for PKCE callback error: %v", ctx.Err())
		}
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

func testPKCERedirectURI(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	addr := listener.Addr().String()
	_ = listener.Close()
	return fmt.Sprintf("http://%s/callback", addr)
}

func waitForPKCEListener(t *testing.T, redirectURI string) {
	t.Helper()
	u, err := url.Parse(redirectURI)
	assert.NoError(t, err)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", u.Host, 50*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("pkce listener did not start for %s", redirectURI)
}
