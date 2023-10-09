package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

const (
	DEFAULT_AUTH_COLOR = "blue"
	DEFAULT_AUTH_ICON  = "fingerprint"
)

// Authenticate retrieves an AWS SSO AccessToken from our cache or by
// making the necessary AWS SSO calls.
func (as *AWSSSO) Authenticate(urlAction url.Action, browser string) error {
	log.Tracef("Authenticate(%s, %s)", urlAction, browser)
	// cache urlAction and browser for subsequent calls if necessary
	if urlAction != "" {
		as.urlAction = urlAction
	}

	if browser != "" {
		as.browser = browser
	}

	// check our cache
	token := storage.CreateTokenResponse{}
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &token)
	if err == nil && !token.Expired() {
		as.tokenLock.Lock()
		as.Token = token
		as.tokenLock.Unlock()
		return nil
	} else if err != nil {
		log.Debugf(err.Error())
	} else {
		if token.ExpiresAt != 0 {
			t := time.Unix(token.ExpiresAt, 0)
			log.Infof("Cached SSO token expired at: %s.  Reauthenticating...\n",
				t.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
		} else {
			log.Infof("Cached SSO token has expired.  Reauthenticating...\n")
		}
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

	log.Tracef("reauthenticate() for %s", as.StoreKey())
	err := as.registerClient(false)
	log.Tracef("<- reauthenticate()")
	if err != nil {
		return fmt.Errorf("Unable to register client with AWS SSO: %s", err.Error())
	}

	err = as.startDeviceAuthorization()
	log.Tracef("<- reauthenticate()")
	if err != nil {
		log.Debugf("startDeviceAuthorization failed.  Forcing refresh of registerClient")
		// startDeviceAuthorization can fail if our cached registerClient token is invalid
		if err = as.registerClient(true); err != nil {
			return fmt.Errorf("Unable to register client with AWS SSO: %s", err.Error())
		}
		if err = as.startDeviceAuthorization(); err != nil {
			return fmt.Errorf("Unable to start device authorization with AWS SSO: %s", err.Error())
		}
	}

	auth, err := as.getDeviceAuthInfo()
	log.Tracef("<- reauthenticate()")
	if err != nil {
		return fmt.Errorf("Unable to get device auth info from AWS SSO: %s", err.Error())
	}

	action := as.urlAction
	if as.SSOConfig.AuthUrlAction != url.Undef {
		// specific action for authentication?
		action = as.SSOConfig.AuthUrlAction
	}

	urlOpener := url.NewHandleUrl(action, auth.VerificationUriComplete, as.browser, as.urlExecCommand)
	urlOpener.ContainerSettings(as.StoreKey(), DEFAULT_AUTH_COLOR, DEFAULT_AUTH_ICON)

	if err = urlOpener.Open(); err != nil {
		return err
	}

	log.Infof("Waiting for SSO authentication...")

	err = as.createToken()
	if err != nil {
		return fmt.Errorf("Unable to create new AWS SSO token: %s", err.Error())
	}

	return nil
}

const (
	awsSSOClientName = "aws-sso-cli"
	awsSSOClientType = "public"
	awsSSOGrantType  = "urn:ietf:params:oauth:grant-type:device_code"
	// The default values for ODIC defined in:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	SLOW_DOWN_SEC  = 5
	RETRY_INTERVAL = 5
)

// registerClient does the needful to talk to AWS or read our cache to get the
// RegisterClientData for later steps and saves it to our secret store
func (as *AWSSSO) registerClient(force bool) error {
	log.Tracef("registerClient()")
	if !force {
		err := as.store.GetRegisterClientData(as.StoreKey(), &as.ClientData)
		if err == nil && !as.ClientData.Expired() {
			log.Debugf("Using RegisterClient cache for %s", as.StoreKey())
			return nil
		}
	}

	input := ssooidc.RegisterClientInput{
		ClientName: aws.String(as.ClientName),
		ClientType: aws.String(as.ClientType),
		Scopes:     nil,
	}
	resp, err := as.ssooidc.RegisterClient(context.TODO(), &input)
	if err != nil {
		return err
	}

	as.ClientData = storage.RegisterClientData{
		AuthorizationEndpoint: aws.ToString(resp.AuthorizationEndpoint), // not used?
		ClientId:              aws.ToString(resp.ClientId),
		ClientSecret:          aws.ToString(resp.ClientSecret),
		ClientIdIssuedAt:      resp.ClientIdIssuedAt,
		ClientSecretExpiresAt: resp.ClientSecretExpiresAt,
		TokenEndpoint:         aws.ToString(resp.TokenEndpoint), // not used?
	}
	err = as.store.SaveRegisterClientData(as.StoreKey(), as.ClientData)
	if err != nil {
		log.WithError(err).Errorf("Unable to save RegisterClientData for %s", as.StoreKey())
	}
	return nil
}

// startDeviceAuthorization makes the call to AWS to initiate the OIDC auth
// to the SSO provider.
func (as *AWSSSO) startDeviceAuthorization() error {
	log.Tracef("startDeviceAuthorization() for %s", as.StoreKey())
	input := ssooidc.StartDeviceAuthorizationInput{
		StartUrl:     aws.String(as.StartUrl),
		ClientId:     aws.String(as.ClientData.ClientId),
		ClientSecret: aws.String(as.ClientData.ClientSecret),
	}
	resp, err := as.ssooidc.StartDeviceAuthorization(context.TODO(), &input)
	if err != nil {
		return err
	}

	as.DeviceAuth = storage.StartDeviceAuthData{
		DeviceCode:              aws.ToString(resp.DeviceCode),
		UserCode:                aws.ToString(resp.UserCode),
		VerificationUri:         aws.ToString(resp.VerificationUri),
		VerificationUriComplete: aws.ToString(resp.VerificationUriComplete),
		ExpiresIn:               resp.ExpiresIn,
		Interval:                resp.Interval,
	}
	log.Debugf("Created OIDC device code for %s (expires in: %ds)",
		as.StoreKey(), as.DeviceAuth.ExpiresIn)

	fmt.Fprintf(os.Stderr, "\tVerify this code in your browser: %s\n", as.DeviceAuth.UserCode)

	return nil
}

type DeviceAuthInfo struct {
	VerificationUri         string
	VerificationUriComplete string
	UserCode                string
}

// getDeviceAuthInfo generates a DeviceAuthInfo struct
func (as *AWSSSO) getDeviceAuthInfo() (DeviceAuthInfo, error) {
	log.Tracef("getDeviceAuthInfo()")
	if as.DeviceAuth.VerificationUri == "" {
		return DeviceAuthInfo{}, fmt.Errorf("No valid verification url is available for %s", as.StoreKey())
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
	log.Tracef("createToken()")
	input := ssooidc.CreateTokenInput{
		ClientId:     aws.String(as.ClientData.ClientId),
		ClientSecret: aws.String(as.ClientData.ClientSecret),
		DeviceCode:   aws.String(as.DeviceAuth.DeviceCode),
		GrantType:    aws.String(awsSSOGrantType),
		// RefreshToken is not supported by AWS
	}

	// figure out our timings
	var slowDown = SLOW_DOWN_SEC * time.Second
	var retryInterval = RETRY_INTERVAL * time.Second
	if as.DeviceAuth.Interval > 0 {
		retryInterval = time.Duration(as.DeviceAuth.Interval) * time.Second
	}

	var err error
	var resp *ssooidc.CreateTokenOutput

	for {
		resp, err = as.ssooidc.CreateToken(context.TODO(), &input)
		if err == nil {
			break
		}

		var sde *oidctypes.SlowDownException
		var ape *oidctypes.AuthorizationPendingException

		if errors.As(err, &sde) {
			log.Debugf("Slowing down CreateToken()")
			retryInterval += slowDown
			time.Sleep(retryInterval)
		} else if errors.As(err, &ape) {
			time.Sleep(retryInterval)
		} else {
			return fmt.Errorf("createToken: %s", err.Error())
		}
	}

	secs, _ := time.ParseDuration(fmt.Sprintf("%ds", resp.ExpiresIn)) // seconds
	as.tokenLock.Lock()
	as.Token = storage.CreateTokenResponse{
		AccessToken:  aws.ToString(resp.AccessToken),
		ExpiresIn:    resp.ExpiresIn,
		ExpiresAt:    time.Now().Add(secs).Unix(),
		IdToken:      aws.ToString(resp.IdToken),      // per AWS docs, this may be undefined
		RefreshToken: aws.ToString(resp.RefreshToken), // per AWS docs, not currently implemented
		TokenType:    aws.ToString(resp.TokenType),
	}
	as.tokenLock.Unlock()
	as.tokenLock.RLock()
	err = as.store.SaveCreateTokenResponse(as.StoreKey(), as.Token)
	as.tokenLock.RUnlock()
	if err != nil {
		log.WithError(err).Errorf("Unable to save CreateTokenResponse")
	}

	return nil
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
			log.WithError(err).Errorf("Unable to delete AccessToken from secure store")
		}
	}

	input := &sso.LogoutInput{
		AccessToken: aws.String(token),
	}

	// do the needful
	_, err := as.sso.Logout(context.TODO(), input)
	return err
}
