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
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestStartPKCEAuthCodeFlow(t *testing.T) {
	t.Run("success with generated state", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		flow, err := client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
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

		flow, err := client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
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

		_, err := client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorization endpoint is required")

		_, err = client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "https://auth.example.com/authorize",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client id is required")

		_, err = client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "https://auth.example.com/authorize",
			ClientID:              "client-id",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect uri is required")

		_, err = client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "://bad-url",
			ClientID:              "client-id",
			RedirectURI:           "http://localhost:12345/callback",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid authorization endpoint")

		// URL that parses without error but has no scheme or host
		_, err = client.StartPKCEAuthCodeFlow(context.Background(), StartPKCEAuthCodeInput{
			AuthorizationEndpoint: "not-a-url-just-a-path",
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
			assert.Equal(t, string(storage.GrantTypeAuthorizationCode), aws.ToString(in.GrantType))
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

		_, err = client.ExchangePKCEAuthCode(context.Background(), ExchangePKCEAuthCodeInput{
			ClientID: "client-id",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorization code is required")

		_, err = client.ExchangePKCEAuthCode(context.Background(), ExchangePKCEAuthCodeInput{
			ClientID: "client-id",
			Code:     "auth-code",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "code verifier is required")

		_, err = client.ExchangePKCEAuthCode(context.Background(), ExchangePKCEAuthCodeInput{
			ClientID:     "client-id",
			Code:         "auth-code",
			CodeVerifier: "verifier",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect uri is required")
	})
}

func TestWaitForPKCECallback(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})

		_, err := client.WaitForPKCECallback(context.Background(), WaitForPKCECallbackInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redirect uri is required")

		_, err = client.WaitForPKCECallback(context.Background(), WaitForPKCECallbackInput{
			RedirectURI: "http://127.0.0.1:12345/callback",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected state is required")

		// URL that parses but has no scheme/host
		_, err = client.WaitForPKCECallback(context.Background(), WaitForPKCECallbackInput{
			RedirectURI:   "not-a-url",
			ExpectedState: "state",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid redirect uri")
	})

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
		err := pkceCallbackError(t, "expected-state", "?code=auth-code&state=wrong-state")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "state mismatch")
	})

	t.Run("missing code in callback", func(t *testing.T) {
		err := pkceCallbackError(t, "expected-state", "?state=expected-state")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing authorization code")
	})

	t.Run("redirect uri without path exercises default path", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		// Allocate a free port, then use a redirect URI with no path so path defaults to "/"
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		assert.NoError(t, err)
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		redirectURI := fmt.Sprintf("http://127.0.0.1:%d", port)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resultCh := make(chan PKCECallback, 1)
		errCh := make(chan error, 1)
		go func() {
			callback, err := client.WaitForPKCECallback(ctx, WaitForPKCECallbackInput{
				RedirectURI:   redirectURI,
				ExpectedState: "my-state",
			})
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- callback
		}()

		waitForPKCEListener(t, redirectURI+"/")

		resp, err := http.Get(fmt.Sprintf("%s/?code=my-code&state=my-state", redirectURI))
		assert.NoError(t, err)
		if resp != nil {
			_ = resp.Body.Close()
		}

		select {
		case callback := <-resultCh:
			assert.Equal(t, "my-code", callback.Code)
		case err := <-errCh:
			assert.NoError(t, err)
		case <-ctx.Done():
			t.Fatalf("timed out: %v", ctx.Err())
		}
	})

	t.Run("context canceled before callback", func(t *testing.T) {
		client := NewAWSWithAPI(&mockOIDCAPI{})
		redirectURI := testPKCERedirectURI(t)
		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			_, err := client.WaitForPKCECallback(ctx, WaitForPKCECallbackInput{
				RedirectURI:   redirectURI,
				ExpectedState: "expected-state",
			})
			errCh <- err
		}()

		waitForPKCEListener(t, redirectURI)
		cancel()

		select {
		case err := <-errCh:
			assert.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for context cancellation")
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

// pkceCallbackError starts a WaitForPKCECallback listener, sends an HTTP GET with
// the given query string, and returns the error from the callback handler.
func pkceCallbackError(t *testing.T, expectedState, query string) error {
	t.Helper()
	client := NewAWSWithAPI(&mockOIDCAPI{})
	redirectURI := testPKCERedirectURI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.WaitForPKCECallback(ctx, WaitForPKCECallbackInput{
			RedirectURI:   redirectURI,
			ExpectedState: expectedState,
		})
		errCh <- err
	}()

	waitForPKCEListener(t, redirectURI)

	resp, err := http.Get(redirectURI + query) //nolint:noctx
	assert.NoError(t, err)
	if resp != nil {
		_ = resp.Body.Close()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		t.Fatalf("timed out waiting for PKCE callback error")
		return nil
	}
}
