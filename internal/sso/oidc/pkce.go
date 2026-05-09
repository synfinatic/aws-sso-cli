package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func (c *AWSClient) StartPKCEAuthCodeFlow(in StartPKCEAuthCodeInput) (PKCEAuthCodeFlow, error) {
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

func ValidatePKCEState(expected, got string) error {
	if expected == "" {
		return fmt.Errorf("expected state is empty")
	}
	if got == "" {
		return fmt.Errorf("returned state is empty")
	}
	if expected != got {
		return fmt.Errorf("state mismatch")
	}
	return nil
}

func randomURLSafeString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
