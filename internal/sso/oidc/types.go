package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// API is the low-level AWS SSO OIDC client surface used by this package.
type API interface {
	RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// Client is the higher-level OIDC interface consumed by the sso package.
// It intentionally supports generic token creation input so additional
// workflows (for example PKCE authorization_code) can be added incrementally.
type Client interface {
	RegisterClient(context.Context, RegisterClientInput) (storage.RegisterClientData, error)
	StartDeviceAuthorization(context.Context, StartDeviceAuthorizationInput) (storage.StartDeviceAuthData, error)
	CreateToken(context.Context, CreateTokenInput) (storage.CreateTokenResponse, error)
	PollDeviceCodeToken(context.Context, PollDeviceCodeTokenInput) (storage.CreateTokenResponse, error)
	StartPKCEAuthCodeFlow(StartPKCEAuthCodeInput) (PKCEAuthCodeFlow, error)
	WaitForPKCECallback(context.Context, WaitForPKCECallbackInput) (PKCECallback, error)
	ExchangePKCEAuthCode(context.Context, ExchangePKCEAuthCodeInput) (storage.CreateTokenResponse, error)
}

const (
	GrantTypeDeviceCode         = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeAuthorizationCode  = "authorization_code"
	PKCECodeChallengeMethodS256 = "S256"

	defaultCodeVerifierBytes = 48
	defaultStateBytes        = 24
)

type AuthWorkflow string

const (
	AuthWorkflowDeviceCode AuthWorkflow = "device_code"
	AuthWorkflowPKCE       AuthWorkflow = "pkce"
)

func (w AuthWorkflow) Valid() bool {
	switch w {
	case AuthWorkflowDeviceCode, AuthWorkflowPKCE:
		return true
	default:
		return false
	}
}

func (w AuthWorkflow) OrDefault() AuthWorkflow {
	if w == "" {
		return AuthWorkflowPKCE
	}
	return w
}

func ValidateAuthWorkflow(w AuthWorkflow) error {
	w = w.OrDefault()
	if !w.Valid() {
		return fmt.Errorf("invalid AuthWorkflow %q: must be %q or %q", w, AuthWorkflowDeviceCode, AuthWorkflowPKCE)
	}
	return nil
}

type RegisterClientInput struct {
	ClientName   string
	ClientType   string
	GrantTypes   []string
	IssuerUrl    string
	RedirectUris []string
	Scopes       []string
}

type StartDeviceAuthorizationInput struct {
	StartURL     string
	ClientID     string
	ClientSecret string // nolint:gosec
}

type CreateTokenInput struct {
	ClientID     string
	ClientSecret string // nolint:gosec
	GrantType    string
	DeviceCode   string
	Code         string
	CodeVerifier string
	RedirectURI  string
}

type PollDeviceCodeTokenInput struct {
	CreateTokenInput
	RetryInterval time.Duration
	SlowDown      time.Duration
}

type StartPKCEAuthCodeInput struct {
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	Scopes                []string
	State                 string
}

type PKCEAuthCodeFlow struct {
	AuthorizationURL    string
	State               string
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

type WaitForPKCECallbackInput struct {
	RedirectURI   string
	ExpectedState string
}

type PKCECallback struct {
	Code string
}

type ExchangePKCEAuthCodeInput struct {
	ClientID     string
	ClientSecret string // nolint:gosec
	Code         string
	CodeVerifier string
	RedirectURI  string
}
