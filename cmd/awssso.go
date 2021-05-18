package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	"fmt"
	"time"

	/*
		"github.com/aws/aws-sdk-go/aws/client"
		"github.com/aws/aws-sdk-go/aws/awserr"
		"github.com/aws/aws-sdk-go/aws/credentials"
		"github.com/aws/aws-sdk-go/service/sso"
		"github.com/aws/aws-sdk-go/service/sts"
		"github.com/skratchdot/open-golang/open" // default opener
	*/
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	log "github.com/sirupsen/logrus"
)

// Define the interface for storing our AWS SSO data
type SecureStorage interface {
	SaveRegisterClientData(string, RegisterClientData) error
	GetRegisterClientData(string, *RegisterClientData) error
	DeleteRegisterClientData(string) error
	/*
		SaveStartDeviceAuthData(string, StartDeviceAuthData) error
		GetStartDeviceAuthData(string, *StartDeviceAuthData) error
		DeleteStartDeviceAuthData(string) error
	*/
}

type AWSSSO struct {
	ssooidc         ssooidc.SSOOIDC
	store           SecureStorage
	ClientName      string              `json:"ClientName"`
	ClientType      string              `json:"ClientType"`
	ssoRegion       string              `json:"ssoRegion"`
	startUrl        string              `json:"startUrl"`
	registerClient  RegisterClientData  `json:"RegisterClient"`
	startDeviceAuth StartDeviceAuthData `json:"StartDeviceAuth"`
	tokenResponse   CreateTokenResponse `json:"TokenResponse"`
}

func NewAWSSSO(region, ssoRegion, startUrl string, store *SecureStorage) *AWSSSO {
	mySession := session.Must(session.NewSession())
	svc := ssooidc.New(mySession, aws.NewConfig().WithRegion(region))

	as := AWSSSO{
		ssooidc:    *svc,
		store:      *store,
		ClientName: awsSSOClientName,
		ClientType: awsSSOClientType,
		ssoRegion:  ssoRegion,
		startUrl:   startUrl,
	}
	return &as
}

func (as *AWSSSO) storeKey() string {
	return fmt.Sprintf("%s:%s", as.ssoRegion, as.startUrl)
}

const (
	awsSSOClientName = "aws-sso-cli"
	awsSSOClientType = "public"
	awsSSOGrantType  = "urn:ietf:params:oauth:grant-type:device_code"
)

// this struct should be cached for long term if possible
type RegisterClientData struct {
	ClientName            string `json:"clientName"`
	ClientType            string `json:"clientType"`
	ClientId              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientIdIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	// Not sure if these fields are needed?
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json"tokenEndpoint"`
}

// Does the needful to talk to AWS or read our cache to get the RegisterClientData
func (as *AWSSSO) RegisterClient() error {
	err := as.store.GetRegisterClientData(as.storeKey(), &as.registerClient)
	// XXX: I think an hour buffer here is fine?
	if err == nil && as.registerClient.ClientSecretExpiresAt > time.Now().Add(time.Hour).Unix() {
		return nil
	}

	input := ssooidc.RegisterClientInput{
		ClientName: aws.String(as.ClientName),
		ClientType: aws.String(as.ClientType),
		Scopes:     nil,
	}
	resp, err := as.ssooidc.RegisterClient(&input)
	if err != nil {
		return err
	}

	as.registerClient = RegisterClientData{
		ClientId:              *resp.ClientId,
		ClientSecret:          *resp.ClientSecret,
		ClientIdIssuedAt:      *resp.ClientIdIssuedAt,
		ClientSecretExpiresAt: *resp.ClientSecretExpiresAt,
		AuthorizationEndpoint: *resp.AuthorizationEndpoint,
		TokenEndpoint:         *resp.TokenEndpoint,
	}
	err = as.store.SaveRegisterClientData(as.storeKey(), as.registerClient)
	if err != nil {
		log.WithError(err).Errorf("Unable to save RegisterClientData")
	}
	return nil
}

type StartDeviceAuthData struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationUri         string `json:"verificationUri"`
	VerificationUriComplete string `json:"verificationUriComplete"`
	ExpiresIn               int64  `json:"expiresIn"`
	Interval                int64  `json:"interval"`
}

// Makes the call to AWS to initiate the OIDC auth to the SSO provider.
func (as *AWSSSO) StartDeviceAuthorization() error {
	input := ssooidc.StartDeviceAuthorizationInput{
		ClientId:     aws.String(as.registerClient.ClientId),
		ClientSecret: aws.String(as.registerClient.ClientSecret),
	}
	resp, err := as.ssooidc.StartDeviceAuthorization(&input)
	if err != nil {
		return err
	}

	as.startDeviceAuth = StartDeviceAuthData{
		DeviceCode:              *resp.DeviceCode,
		UserCode:                *resp.UserCode,
		VerificationUri:         *resp.VerificationUri,
		VerificationUriComplete: *resp.VerificationUriComplete,
		ExpiresIn:               *resp.ExpiresIn,
		Interval:                *resp.Interval,
	}
	return nil
}

type DeviceAuthInfo struct {
	VerificationUri         string
	VerificationUriComplete string
	UserCode                string
}

func (as *AWSSSO) GetDeviceAuthInfo() (DeviceAuthInfo, error) {
	if as.startDeviceAuth.VerificationUri == "" {
		return DeviceAuthInfo{}, fmt.Errorf("No valid verification url is available")
	}

	info := DeviceAuthInfo{
		VerificationUri:         as.startDeviceAuth.VerificationUri,
		VerificationUriComplete: as.startDeviceAuth.VerificationUriComplete,
		UserCode:                as.startDeviceAuth.UserCode,
	}
	return info, nil
}

type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"` // should be cached to issue new creds
	ExpiresIn    int64  `json:"expiresIn"`
	IdToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"tokenType"`
}

func (as *AWSSSO) CreateToken() error {
	input := ssooidc.CreateTokenInput{
		ClientId:     aws.String(as.registerClient.ClientId),
		ClientSecret: aws.String(as.registerClient.ClientSecret),
		DeviceCode:   aws.String(as.startDeviceAuth.DeviceCode),
		GrantType:    aws.String(awsSSOGrantType),
	}

	resp, err := as.ssooidc.CreateToken(&input)
	if err != nil {
		return err
	}

	as.tokenResponse = CreateTokenResponse{
		AccessToken:  *resp.AccessToken,
		ExpiresIn:    *resp.ExpiresIn,
		IdToken:      *resp.IdToken,
		RefreshToken: *resp.RefreshToken,
		TokenType:    *resp.TokenType,
	}
	return nil
}

type RoleCredentialsResponse struct {
	Credentials RoleCredentials `json:"roleCredentials"`
}

type RoleCredentials struct { // Cache
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      uint64 `json:"expiration"`
}
