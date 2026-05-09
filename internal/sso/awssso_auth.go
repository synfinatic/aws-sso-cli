package sso

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
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

const (
	DEFAULT_AUTH_COLOR = "blue"
	DEFAULT_AUTH_ICON  = "fingerprint"
	VERIFY_MSG         = "\n\tVerify this code in your browser: %s\n"
	PKCE_MSG           = "\n\tComplete PKCE authorization in your browser and paste the redirected URL:\n"
)

// ValidAuthToken returns true if we have a valid AWS SSO authentication token
// or false if we need to authenticate.
func (as *AWSSSO) ValidAuthToken() bool {
	// check our cache
	token := storage.CreateTokenResponse{}
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &token)
	if err != nil {
		log.Debug(err.Error())
		return false
	}

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
	return false
}

// Authenticate retrieves an AWS SSO AccessToken from our cache or by
// making the necessary AWS SSO calls.
func (as *AWSSSO) Authenticate(urlAction uri.Action, browser string) error {
	log.Trace("Authenticate", "urlAction", urlAction, "browser", browser)
	// cache urlAction and browser for subsequent calls if necessary
	// if action is still undefined, use the default action which is defined inside NewHandleUrl()
	as.urlAction = urlAction

	if browser != "" {
		as.browser = browser
	}

	return as.reauthenticate()
}

// StoreKey returns the key in the cache for this AWSSSO instance
func (as *AWSSSO) StoreKey() string {
	return as.key
}

// reauthenticate talks to AWS SSO to generate a new AWS SSO AccessToken
func (as *AWSSSO) reauthenticate() error {
	// This should only be happening one at a time!
	as.authenticateLock.Lock()
	defer as.authenticateLock.Unlock()

	log.Trace("reauthenticate()", "storeKey", as.StoreKey())
	err := as.registerClient(false)
	if err != nil {
		return fmt.Errorf("unable to register client with AWS SSO: %s", err.Error())
	}
	log.Trace("<- reauthenticate()")

	switch as.getAuthWorkflow() {
	case oidc.AuthWorkflowDeviceCode:
		return as.reauthenticateDeviceCode()
	case oidc.AuthWorkflowPKCE:
		return as.reauthenticatePKCE()
	default:
		return fmt.Errorf("unsupported auth workflow: %s", as.getAuthWorkflow())
	}
}

const (
	awsSSOClientName = "aws-sso-cli"
	awsSSOClientType = "public"
	// The default values for ODIC defined in:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	SLOW_DOWN_SEC  = 5
	RETRY_INTERVAL = 5
)

// registerClient does the needful to talk to AWS or read our cache to get the
// RegisterClientData for later steps and saves it to our secret store
func (as *AWSSSO) registerClient(force bool) error {
	log.Trace("registerClient()")
	oidcClient := oidc.NewAWSWithAPI(as.ssooidc)
	if !force {
		log.Trace("Checking cache for RegisterClientData", "storeKey", as.StoreKey())
		err := as.store.GetRegisterClientData(as.StoreKey(), &as.ClientData)
		if err == nil && !as.ClientData.Expired() {
			log.Debug("Using RegisterClient cache", "storeKey", as.StoreKey())
			return nil
		}
	}

	log.Trace("Registering new client with AWS SSO", "ClientName", as.ClientName, "ClientType", as.ClientType)
	resp, err := oidcClient.RegisterClient(context.TODO(), oidc.RegisterClientInput{
		ClientName: as.ClientName,
		ClientType: as.ClientType,
		GrantTypes: as.authGrantTypes(),
		Scopes:     nil,
	})
	if err != nil {
		return err
	}
	log.Trace("Registered new client with AWS SSO", "ClientId", resp.ClientId, "ClientSecretExpiresAt", resp.ClientSecretExpiresAt)

	as.ClientData = resp
	log.Trace("SaveRegisterClientData start", "storeKey", as.StoreKey())
	err = as.store.SaveRegisterClientData(as.StoreKey(), as.ClientData)
	if err != nil {
		log.Error("unable to save RegisterClientData", "storeKey", as.StoreKey(), "error", err.Error())
	}
	log.Trace("SaveRegisterClientData complete", "storeKey", as.StoreKey())
	return nil
}

// startDeviceAuthorization makes the call to AWS to initiate the OIDC auth
// to the SSO provider.
func (as *AWSSSO) startDeviceAuthorization() error {
	log.Trace("startDeviceAuthorization()", "storeKey", as.StoreKey())
	oidcClient := oidc.NewAWSWithAPI(as.ssooidc)
	resp, err := oidcClient.StartDeviceAuthorization(context.TODO(), oidc.StartDeviceAuthorizationInput{
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
func (as *AWSSSO) createToken() error {
	log.Trace("createToken()")
	oidcClient := oidc.NewAWSWithAPI(as.ssooidc)
	var slowDown = SLOW_DOWN_SEC * time.Second
	var retryInterval = RETRY_INTERVAL * time.Second
	if as.DeviceAuth.Interval > 0 {
		retryInterval = time.Duration(as.DeviceAuth.Interval) * time.Second
	}

	token, err := oidcClient.PollDeviceCodeToken(context.TODO(), oidc.PollDeviceCodeTokenInput{
		CreateTokenInput: oidc.CreateTokenInput{
			ClientID:     as.ClientData.ClientId,
			ClientSecret: as.ClientData.ClientSecret,
			DeviceCode:   as.DeviceAuth.DeviceCode,
			GrantType:    oidc.GrantTypeDeviceCode,
		},
		RetryInterval: retryInterval,
		SlowDown:      slowDown,
	})
	if err != nil {
		return err
	}

	return as.saveToken(token)
}

func (as *AWSSSO) saveToken(token storage.CreateTokenResponse) error {
	as.tokenLock.Lock()
	as.Token = token
	as.tokenLock.Unlock()
	as.tokenLock.RLock()
	err := as.store.SaveCreateTokenResponse(as.StoreKey(), as.Token)
	as.tokenLock.RUnlock()
	if err != nil {
		log.Error("unable to save CreateTokenResponse", "error", err.Error())
	}

	return nil
}

func (as *AWSSSO) getAuthWorkflow() oidc.AuthWorkflow {
	if as.SSOConfig == nil {
		return oidc.AuthWorkflowDeviceCode
	}
	return as.SSOConfig.AuthWorkflow.OrDefault()
}

func (as *AWSSSO) authGrantTypes() []string {
	if as.getAuthWorkflow() == oidc.AuthWorkflowPKCE {
		return []string{"refresh_token", oidc.GrantTypeAuthorizationCode}
	}
	return []string{"refresh_token"}
}

func (as *AWSSSO) pkceRedirectURI() string {
	return "http://127.0.0.1:8250/callback"
}

func (as *AWSSSO) readPKCECallbackURL() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		if len(strings.TrimSpace(line)) == 0 {
			return "", err
		}
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("empty callback url")
	}
	return line, nil
}

func (as *AWSSSO) parsePKCECode(callbackURL string, expectedState string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	state := q.Get("state")
	if err = oidc.ValidatePKCEState(expectedState, state); err != nil {
		return "", err
	}

	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("missing authorization code")
	}

	return code, nil
}

func (as *AWSSSO) reauthenticateDeviceCode() error {
	err := as.startDeviceAuthorization()
	log.Trace("<- reauthenticate()")
	if err != nil {
		log.Debug("startDeviceAuthorization failed.  Forcing refresh of registerClient")
		// startDeviceAuthorization can fail if our cached registerClient token is invalid
		if err = as.registerClient(true); err != nil {
			return fmt.Errorf("unable to register client with AWS SSO: %s", err.Error())
		}
		if err = as.startDeviceAuthorization(); err != nil {
			return fmt.Errorf("unable to start device authorization with AWS SSO: %s", err.Error())
		}
	}

	auth, err := as.getDeviceAuthInfo()
	log.Trace("<- reauthenticate()")
	if err != nil {
		return fmt.Errorf("unable to get device auth info from AWS SSO: %s", err.Error())
	}

	urlOpener := uri.NewHandleUrl(as.urlAction, auth.VerificationUriComplete, as.browser, as.urlExecCommand)
	urlOpener.ContainerSettings(as.StoreKey(), DEFAULT_AUTH_COLOR, DEFAULT_AUTH_ICON)

	if err = urlOpener.Open(); err != nil {
		return err
	}

	log.Info("Waiting for SSO authentication...")

	err = as.createToken()
	if err != nil {
		return fmt.Errorf("unable to create new AWS SSO token: %s", err.Error())
	}

	return nil
}

func (as *AWSSSO) reauthenticatePKCE() error {
	oidcClient := oidc.NewAWSWithAPI(as.ssooidc)

	if as.ClientData.AuthorizationEndpoint == "" {
		if err := as.registerClient(true); err != nil {
			return fmt.Errorf("unable to register client with AWS SSO: %s", err.Error())
		}
	}

	flow, err := oidcClient.StartPKCEAuthCodeFlow(oidc.StartPKCEAuthCodeInput{
		AuthorizationEndpoint: as.ClientData.AuthorizationEndpoint,
		ClientID:              as.ClientData.ClientId,
		RedirectURI:           as.pkceRedirectURI(),
	})
	if err != nil {
		return fmt.Errorf("unable to start pkce authorization with AWS SSO: %s", err.Error())
	}

	urlOpener := uri.NewHandleUrl(as.urlAction, flow.AuthorizationURL, as.browser, as.urlExecCommand)
	urlOpener.ContainerSettings(as.StoreKey(), DEFAULT_AUTH_COLOR, DEFAULT_AUTH_ICON)
	if err = urlOpener.Open(); err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, PKCE_MSG)
	callback, err := as.readPKCECallbackURL()
	if err != nil {
		return fmt.Errorf("unable to read pkce callback url: %s", err.Error())
	}

	code, err := as.parsePKCECode(callback, flow.State)
	if err != nil {
		return fmt.Errorf("unable to parse pkce callback url: %s", err.Error())
	}

	token, err := oidcClient.ExchangePKCEAuthCode(context.TODO(), oidc.ExchangePKCEAuthCodeInput{
		ClientID:     as.ClientData.ClientId,
		ClientSecret: as.ClientData.ClientSecret,
		Code:         code,
		CodeVerifier: flow.CodeVerifier,
		RedirectURI:  as.pkceRedirectURI(),
	})
	if err != nil {
		return fmt.Errorf("unable to exchange pkce authorization code: %s", err.Error())
	}

	return as.saveToken(token)
}

// Logout performs an SSO logout with AWS and invalidates our SSO session
func (as *AWSSSO) Logout() error {
	token := as.Token.AccessToken

	if token == "" {
		// Fetch our access token from our secure store
		tr := storage.CreateTokenResponse{}
		if err := as.store.GetCreateTokenResponse(as.key, &tr); err != nil {
			return err
		}
		token = tr.AccessToken

		// delete the value from the store so we don't think we have a valid token
		if err := as.store.DeleteCreateTokenResponse(as.key); err != nil {
			log.Error("unable to delete AccessToken from secure store", "error", err.Error())
		}
	}

	input := &sso.LogoutInput{
		AccessToken: aws.String(token),
	}

	// do the needful
	_, err := as.sso.Logout(context.TODO(), input)
	return err
}
