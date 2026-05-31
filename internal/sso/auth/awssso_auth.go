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
	"net"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/synfinatic/aws-sso-cli/internal/prompt"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

const (
	DEFAULT_AUTH_COLOR       = "blue"
	DEFAULT_AUTH_ICON        = "fingerprint"
	VERIFY_MSG               = "\n\tVerify this code in your browser: %s\n"
	SSO_ACCOUNT_ACCESS_SCOPE = "sso:account:access"
	awsSSOClientName         = "aws-sso-cli"
	awsSSOClientType         = "public"
	// The default values for ODIC defined in:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	SLOW_DOWN_SEC  = 5
	RETRY_INTERVAL = 5
)

// ValidAuthToken returns true if we have a valid AWS SSO authentication token
// or false if we need to authenticate.
func (as *AWSSSO) ValidAuthToken(ctx context.Context) bool {
	log.Trace("ValidAuthToken()", "storeKey", as.StoreKey())
	// First verify the stored registration supports refresh tokens. Old
	// registrations (or those written before GrantTypes was persisted) won't
	// have "refresh_token" and must re-register to get a refresh-capable token.
	clientData := storage.RegisterClientData{}
	if err := as.store.GetRegisterClientData(as.StoreKey(), &clientData); err == nil {
		for _, gt := range as.GrantTypes() {
			if !clientData.SupportsGrantType(gt) {
				log.Debug("client registration lacks necessary grant types; forcing new registration",
					"storeKey", as.StoreKey(), "missingGrantType", gt)
				err = as.store.DeleteRegisterClientData(ctx, as.StoreKey())
				if err != nil {
					log.Error("unable to delete RegisterClientData from secure store", "storeKey", as.StoreKey(), "error", err.Error())
				}
				return false
			}
		}
	}

	// check our cache
	token := storage.CreateTokenResponse{}
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &token)
	if err != nil {
		log.Debug(err.Error())
		return false
	}

	// happy path
	if !token.Expired() {
		as.tokenLock.Lock()
		as.Token = token
		as.tokenLock.Unlock()
		return true
	}

	if token.ExpiresAt != 0 {
		t := time.Unix(token.ExpiresAt, 0)
		log.Info("Cached SSO token has expired.  Reauthenticating...",
			"time", t.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	} else {
		log.Info("Cached SSO token has expired.  Reauthenticating...")
	}

	// Attempt a silent renewal using the stored refresh token before
	// falling back to a full browser-based re-authentication.
	if token.RefreshToken != "" && as.tryRefreshToken(ctx, token, clientData) {
		return true
	}
	return false
}

// tryRefreshToken attempts to silently renew an expired access token using
// the stored refresh token.  It saves the new token and returns true on
// success, or logs and returns false so the caller can fall back to a full
// re-authentication flow.
func (as *AWSSSO) tryRefreshToken(ctx context.Context, expiredToken storage.CreateTokenResponse, clientData storage.RegisterClientData) bool {
	log.Debug("Attempting silent token refresh", "storeKey", as.StoreKey())
	newToken, err := as.oidcClient.ExchangeRefreshToken(ctx, oidc.ExchangeRefreshTokenInput{
		ClientID:     clientData.ClientId,
		ClientSecret: clientData.ClientSecret,
		RefreshToken: expiredToken.RefreshToken,
	})
	if err != nil {
		log.Debug("Token refresh failed, falling back to full re-authentication", "error", err.Error())
		return false
	}
	if newToken.RefreshToken == "" {
		// AWS may choose not to return a new refresh token; if so, reuse the old one.
		newToken.RefreshToken = expiredToken.RefreshToken
	}
	_ = as.saveToken(ctx, newToken)
	log.Debug("Token successfully refreshed", "storeKey", as.StoreKey())
	return true
}

// Authenticate retrieves an AWS SSO AccessToken from our cache or by
// making the necessary AWS SSO calls.
func (as *AWSSSO) Authenticate(ctx context.Context, urlAction uri.Action, browser string) error {
	log.Trace("Authenticate", "urlAction", urlAction, "browser", browser)
	// cache urlAction and browser for subsequent calls if necessary
	// if action is still undefined, use the default action which is defined inside NewHandleUrl()
	as.urlAction = urlAction

	if browser != "" {
		as.browser = browser
	}

	return as.reauthenticate(ctx)
}

// StoreKey returns the key in the cache for this AWSSSO instance
func (as *AWSSSO) StoreKey() string {
	return as.key
}

// reauthenticate talks to AWS SSO to generate a new AWS SSO AccessToken
func (as *AWSSSO) reauthenticate(ctx context.Context) error {
	// This should only be happening one at a time!
	as.authenticateLock.Lock()
	defer as.authenticateLock.Unlock()

	log.Trace("reauthenticate()", "storeKey", as.StoreKey())
	err := as.registerClient(ctx, false)
	if err != nil {
		return fmt.Errorf("unable to register client with AWS SSO: %w", err)
	}
	log.Trace("<- reauthenticate()")

	switch as.getAuthWorkflow() {
	case oidc.AuthWorkflowDeviceCode:
		return as.reauthenticateDeviceCode(ctx)
	case oidc.AuthWorkflowPKCE:
		return as.reauthenticatePKCE(ctx)
	default:
		log.Fatal("unsupported auth workflow", "workflow", as.getAuthWorkflow())
	}
	return nil
}

// registerClient does the needful to talk to AWS or read our cache to get the
// RegisterClientData for later steps and saves it to our secret store
func (as *AWSSSO) registerClient(ctx context.Context, force bool) error {
	log.Trace("registerClient()")
	if !force {
		log.Trace("Checking cache for RegisterClientData", "storeKey", as.StoreKey())
		err := as.store.GetRegisterClientData(as.StoreKey(), &as.ClientData)
		if err == nil && !as.ClientData.Expired() {
			log.Debug("Using RegisterClient from secure store", "storeKey", as.StoreKey())
			return nil
		}
	}

	log.Trace("Registering new client with AWS SSO", "ClientName", as.ClientName, "ClientType", as.ClientType)
	input := oidc.RegisterClientInput{
		ClientName: as.ClientName,
		ClientType: as.ClientType,
		GrantTypes: as.authGrantTypes(),
		IssuerUrl:  as.StartUrl,
	}
	if as.getAuthWorkflow() == oidc.AuthWorkflowPKCE {
		input.Scopes = []string{SSO_ACCOUNT_ACCESS_SCOPE}
		input.RedirectUris = []string{as.pkceRedirectURIBase()}
	}
	resp, err := as.oidcClient.RegisterClient(ctx, input)
	if err != nil {
		return err
	}
	log.Trace("Registered new client with AWS SSO", "ClientId", resp.ClientId, "ClientSecretExpiresAt", resp.ClientSecretExpiresAt)

	as.ClientData = resp
	// AWS does not echo back the grant types we registered with, so we record
	// them ourselves so ValidAuthToken() can check for refresh_token support.
	as.ClientData.GrantTypes = as.GrantTypes()
	log.Trace("SaveRegisterClientData start", "storeKey", as.StoreKey())
	err = as.store.SaveRegisterClientData(ctx, as.StoreKey(), as.ClientData)
	if err != nil {
		log.Error("unable to save RegisterClientData", "storeKey", as.StoreKey(), "error", err.Error())
	}
	log.Trace("SaveRegisterClientData complete", "storeKey", as.StoreKey())
	return nil
}

// startDeviceAuthorization makes the call to AWS to initiate the OIDC auth
// to the SSO provider.
func (as *AWSSSO) startDeviceAuthorization(ctx context.Context) error {
	log.Trace("startDeviceAuthorization()", "storeKey", as.StoreKey())
	resp, err := as.oidcClient.StartDeviceAuthorization(ctx, oidc.StartDeviceAuthorizationInput{
		StartURL:     as.StartUrl,
		ClientID:     as.ClientData.ClientId,
		ClientSecret: as.ClientData.ClientSecret,
	})
	if err != nil {
		return err
	}

	as.DeviceAuth = resp
	log.Debug("Created OIDC device code", "storeKey", as.StoreKey(), "expires", as.DeviceAuth.ExpiresIn)

	fmt.Fprintf(os.Stderr, VERIFY_MSG, as.DeviceAuth.UserCode)

	return nil
}

type DeviceAuthInfo struct {
	VerificationUri         string
	VerificationUriComplete string
	UserCode                string
}

// getDeviceAuthInfo generates a DeviceAuthInfo struct
func (as *AWSSSO) getDeviceAuthInfo() (DeviceAuthInfo, error) {
	log.Trace("getDeviceAuthInfo()")
	if as.DeviceAuth.VerificationUri == "" {
		return DeviceAuthInfo{}, fmt.Errorf("no valid verification url is available for %s", as.StoreKey())
	}

	info := DeviceAuthInfo{
		VerificationUri:         as.DeviceAuth.VerificationUri,
		VerificationUriComplete: as.DeviceAuth.VerificationUriComplete,
		UserCode:                as.DeviceAuth.UserCode,
	}
	return info, nil
}

// createToken blocks until we have a new SSO AccessToken and saves it
// to our secret store
func (as *AWSSSO) createToken(ctx context.Context) error {
	log.Trace("createToken()")
	var slowDown = SLOW_DOWN_SEC * time.Second
	var retryInterval = RETRY_INTERVAL * time.Second
	if as.DeviceAuth.Interval > 0 {
		retryInterval = time.Duration(as.DeviceAuth.Interval) * time.Second
	}

	input := oidc.PollDeviceCodeTokenInput{
		CreateTokenInput: oidc.CreateTokenInput{
			ClientID:     as.ClientData.ClientId,
			ClientSecret: as.ClientData.ClientSecret,
			DeviceCode:   as.DeviceAuth.DeviceCode,
			GrantType:    storage.GrantTypeDeviceCode,
		},
		RetryInterval: retryInterval,
		SlowDown:      slowDown,
	}
	token, err := as.oidcClient.PollDeviceCodeToken(ctx, input)
	if err != nil {
		return err
	}

	return as.saveToken(ctx, token)
}

func (as *AWSSSO) saveToken(ctx context.Context, token storage.CreateTokenResponse) error {
	as.tokenLock.Lock()
	as.Token = token
	as.tokenLock.Unlock()
	// use the local variable directly to avoid a lock gap
	if err := as.store.SaveCreateTokenResponse(ctx, as.StoreKey(), token); err != nil {
		log.Error("unable to save CreateTokenResponse", "error", err.Error())
	}
	return nil
}

// getAuthWorkflow returns the AuthWorkflow to use for this AWSSSO instance.
// In remote host sessions (SSH/WSL), we default to device_code when unset; otherwise
// we default to PKCE when unset.
func (as *AWSSSO) getAuthWorkflow() oidc.AuthWorkflow {
	if prompt.IsRemoteHost() {
		if as.SSOConfig == nil || as.SSOConfig.AuthWorkflow == "" {
			return oidc.AuthWorkflowDeviceCode
		}
	}

	if as.SSOConfig == nil {
		return oidc.AuthWorkflowPKCE
	}
	return as.SSOConfig.AuthWorkflow.OrDefault()
}

// GrantTypes returns the list of GrantTypes to request in our OIDC client registration, based
// on the AuthWorkflow.
func (as *AWSSSO) GrantTypes() []storage.GrantType {
	log.Debug("GrantTypes()", "authWorkflow", as.getAuthWorkflow())
	switch as.getAuthWorkflow() {
	case oidc.AuthWorkflowDeviceCode:
		return []storage.GrantType{storage.GrantTypeDeviceCode, storage.GrantTypeRefreshToken}
	case oidc.AuthWorkflowPKCE:
		return []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken}
	default:
		log.Fatal("unsupported auth workflow", "workflow", as.getAuthWorkflow())
	}
	return nil
}

func (as *AWSSSO) authGrantTypes() []string {
	grantTypes := []string{}
	for _, gt := range as.GrantTypes() {
		grantTypes = append(grantTypes, string(gt))
	}
	log.Debug("authGrantTypes()", "grantTypes", grantTypes)
	return grantTypes
}

// pkceRedirectURIBase is used in RegisterClient (no port, no path per RFC 8252 §7.3)
func (as *AWSSSO) pkceRedirectURIBase() string {
	return "http://127.0.0.1"
}

// pkceAuthorizationEndpoint returns the OIDC /authorize endpoint URL.
// AWS does not return this from RegisterClient, so we construct it from the region.
func (as *AWSSSO) pkceAuthorizationEndpoint() string {
	if as.ClientData.AuthorizationEndpoint != "" {
		ep := strings.TrimSuffix(as.ClientData.AuthorizationEndpoint, "/")
		if !strings.HasSuffix(ep, "/authorize") {
			ep += "/authorize"
		}
		return ep
	}
	return fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize", as.SsoRegion)
}

func (as *AWSSSO) reauthenticateDeviceCode(ctx context.Context) error {
	err := as.startDeviceAuthorization(ctx)
	log.Trace("<- reauthenticate()")
	if err != nil {
		log.Debug("startDeviceAuthorization failed.  Forcing refresh of registerClient")
		// startDeviceAuthorization can fail if our cached registerClient token is invalid
		if err = as.registerClient(ctx, true); err != nil {
			return fmt.Errorf("unable to register client with AWS SSO: %w", err)
		}
		if err = as.startDeviceAuthorization(ctx); err != nil {
			return fmt.Errorf("unable to start device authorization with AWS SSO: %w", err)
		}
	}

	auth, err := as.getDeviceAuthInfo()
	log.Trace("<- reauthenticate()")
	if err != nil {
		return fmt.Errorf("unable to get device auth info from AWS SSO: %w", err)
	}

	urlOpener := uri.NewHandleUrl(as.urlAction, auth.VerificationUriComplete, as.browser, as.urlExecCommand)
	urlOpener.ContainerSettings(as.StoreKey(), DEFAULT_AUTH_COLOR, DEFAULT_AUTH_ICON)

	if err = urlOpener.Open(); err != nil {
		return err
	}

	log.Info("Waiting for SSO authentication...")

	err = as.createToken(ctx)
	if err != nil {
		return fmt.Errorf("unable to create new AWS SSO token: %w", err)
	}

	return nil
}

func (as *AWSSSO) reauthenticatePKCE(ctx context.Context) error {
	// Find a free loopback port for the callback listener. RFC 8252 §7.3 recommends
	// any available port rather than a fixed one to avoid bind conflicts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("find free port for pkce callback: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d", port)

	flow, err := as.oidcClient.StartPKCEAuthCodeFlow(ctx, oidc.StartPKCEAuthCodeInput{
		AuthorizationEndpoint: as.pkceAuthorizationEndpoint(),
		ClientID:              as.ClientData.ClientId,
		RedirectURI:           redirectURI,
		Scopes:                []string{SSO_ACCOUNT_ACCESS_SCOPE},
	})
	if err != nil {
		return fmt.Errorf("unable to start pkce authorization with AWS SSO: %w", err)
	}

	urlOpener := uri.NewHandleUrl(as.urlAction, flow.AuthorizationURL, as.browser, as.urlExecCommand)
	urlOpener.ContainerSettings(as.StoreKey(), DEFAULT_AUTH_COLOR, DEFAULT_AUTH_ICON)
	if err = urlOpener.Open(); err != nil {
		return err
	}

	// Give the user up to 5 minutes to complete the browser login.
	pkceCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	callback, err := as.oidcClient.WaitForPKCECallback(pkceCtx, oidc.WaitForPKCECallbackInput{
		RedirectURI:   redirectURI,
		ExpectedState: flow.State,
	})
	if err != nil {
		return fmt.Errorf("unable to receive pkce callback: %w", err)
	}

	input := oidc.ExchangePKCEAuthCodeInput{
		ClientID:     as.ClientData.ClientId,
		ClientSecret: as.ClientData.ClientSecret,
		Code:         callback.Code,
		CodeVerifier: flow.CodeVerifier,
		RedirectURI:  redirectURI,
	}
	token, err := as.oidcClient.ExchangePKCEAuthCode(ctx, input)
	if err != nil {
		return fmt.Errorf("unable to exchange pkce authorization code: %w", err)
	}

	return as.saveToken(ctx, token)
}

// Logout performs an SSO logout with AWS and invalidates our SSO session
func (as *AWSSSO) Logout(ctx context.Context) error {
	token := as.Token.AccessToken

	if token == "" {
		// Fetch our access token from our secure store
		tr := storage.CreateTokenResponse{}
		if err := as.store.GetCreateTokenResponse(as.key, &tr); err != nil {
			return err
		}
		token = tr.AccessToken

		// delete the value from the store so we don't think we have a valid token
		if err := as.store.DeleteCreateTokenResponse(ctx, as.key); err != nil {
			log.Error("unable to delete AccessToken from secure store", "error", err.Error())
		}
	}

	input := &awssso.LogoutInput{
		AccessToken: aws.String(token),
	}

	// do the needful
	_, err := as.sso.Logout(ctx, input)
	return err
}
