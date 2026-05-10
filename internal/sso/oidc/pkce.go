package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

const pkceCallbackSuccessHTML = "<html><body><h1>Authentication complete</h1><p>You can close this window and return to aws-sso.</p></body></html>"

func (c *AWSClient) StartPKCEAuthCodeFlow(_ context.Context, in StartPKCEAuthCodeInput) (PKCEAuthCodeFlow, error) {
	if in.AuthorizationEndpoint == "" {
		return PKCEAuthCodeFlow{}, fmt.Errorf("authorization endpoint is required")
	}
	if in.ClientID == "" {
		return PKCEAuthCodeFlow{}, fmt.Errorf("client id is required")
	}
	if in.RedirectURI == "" {
		return PKCEAuthCodeFlow{}, fmt.Errorf("redirect uri is required")
	}

	u, err := url.Parse(in.AuthorizationEndpoint)
	if err != nil {
		return PKCEAuthCodeFlow{}, fmt.Errorf("invalid authorization endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return PKCEAuthCodeFlow{}, fmt.Errorf("invalid authorization endpoint")
	}

	codeVerifier, err := randomURLSafeString(defaultCodeVerifierBytes)
	if err != nil {
		return PKCEAuthCodeFlow{}, fmt.Errorf("unable to generate pkce code verifier: %w", err)
	}

	state := in.State
	if state == "" {
		state, err = randomURLSafeString(defaultStateBytes)
		if err != nil {
			return PKCEAuthCodeFlow{}, fmt.Errorf("unable to generate auth state: %w", err)
		}
	}

	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", in.ClientID)
	q.Set("redirect_uri", in.RedirectURI)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", PKCECodeChallengeMethodS256)
	q.Set("state", state)
	if len(in.Scopes) > 0 {
		q.Set("scope", strings.Join(in.Scopes, " "))
	}
	u.RawQuery = q.Encode()

	return PKCEAuthCodeFlow{
		AuthorizationURL:    u.String(),
		State:               state,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: PKCECodeChallengeMethodS256,
	}, nil
}

func (c *AWSClient) ExchangePKCEAuthCode(ctx context.Context, in ExchangePKCEAuthCodeInput) (storage.CreateTokenResponse, error) {
	if in.ClientID == "" {
		return storage.CreateTokenResponse{}, fmt.Errorf("client id is required")
	}
	if in.Code == "" {
		return storage.CreateTokenResponse{}, fmt.Errorf("authorization code is required")
	}
	if in.CodeVerifier == "" {
		return storage.CreateTokenResponse{}, fmt.Errorf("code verifier is required")
	}
	if in.RedirectURI == "" {
		return storage.CreateTokenResponse{}, fmt.Errorf("redirect uri is required")
	}

	return c.CreateToken(ctx, CreateTokenInput{
		ClientID:     in.ClientID,
		ClientSecret: in.ClientSecret,
		GrantType:    GrantTypeAuthorizationCode,
		Code:         in.Code,
		CodeVerifier: in.CodeVerifier,
		RedirectURI:  in.RedirectURI,
	})
}

func (c *AWSClient) WaitForPKCECallback(ctx context.Context, in WaitForPKCECallbackInput) (PKCECallback, error) {
	if in.RedirectURI == "" {
		return PKCECallback{}, fmt.Errorf("redirect uri is required")
	}
	if in.ExpectedState == "" {
		return PKCECallback{}, fmt.Errorf("expected state is required")
	}

	redirectURL, err := url.Parse(in.RedirectURI)
	if err != nil {
		return PKCECallback{}, fmt.Errorf("invalid redirect uri: %w", err)
	}
	if redirectURL.Scheme == "" || redirectURL.Host == "" {
		return PKCECallback{}, fmt.Errorf("invalid redirect uri")
	}

	path := redirectURL.EscapedPath()
	if path == "" {
		path = "/"
	}

	listener, err := net.Listen("tcp", redirectURL.Host)
	if err != nil {
		return PKCECallback{}, fmt.Errorf("listen for pkce callback: %w", err)
	}
	defer listener.Close()

	callbackCh := make(chan PKCECallback, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	server := &http.Server{
		ReadHeaderTimeout: time.Duration(5) * time.Second,
		Handler:           mux,
	}

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		callback, callbackErr := parsePKCECallback(r.URL, in.ExpectedState)
		if callbackErr != nil {
			http.Error(w, callbackErr.Error(), http.StatusBadRequest)
			select {
			case errCh <- callbackErr:
			default:
			}
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(pkceCallbackSuccessHTML))

		select {
		case callbackCh <- callback:
		default:
		}
	})

	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			select {
			case errCh <- serveErr:
			default:
			}
		}
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	select {
	case callback := <-callbackCh:
		return callback, nil
	case err = <-errCh:
		return PKCECallback{}, err
	case <-ctx.Done():
		return PKCECallback{}, ctx.Err()
	}
}

func ValidatePKCEState(expected, got string) error {
	if expected == "" {
		return fmt.Errorf("expected state is empty")
	}
	if got == "" {
		return fmt.Errorf("returned state is empty")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
		return fmt.Errorf("state mismatch")
	}
	return nil
}

func parsePKCECallback(callbackURL *url.URL, expectedState string) (PKCECallback, error) {
	state := callbackURL.Query().Get("state")
	if err := ValidatePKCEState(expectedState, state); err != nil {
		return PKCECallback{}, err
	}

	code := callbackURL.Query().Get("code")
	if code == "" {
		return PKCECallback{}, fmt.Errorf("missing authorization code")
	}

	return PKCECallback{Code: code}, nil
}

func randomURLSafeString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
