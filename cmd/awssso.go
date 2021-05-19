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
	"reflect"
	"time"

	/*
		"github.com/aws/aws-sdk-go/aws/client"
		"github.com/aws/aws-sdk-go/aws/awserr"
		"github.com/aws/aws-sdk-go/aws/credentials"
		"github.com/aws/aws-sdk-go/service/sts"
	*/
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open" // default opener
	"github.com/synfinatic/onelogin-aws-role/utils"
)

type AWSSSO struct {
	sso        sso.SSO
	ssooidc    ssooidc.SSOOIDC
	store      SecureStorage
	ClientName string              `json:"ClientName"`
	ClientType string              `json:"ClientType"`
	SsoRegion  string              `json:"ssoRegion"`
	StartUrl   string              `json:"startUrl"`
	ClientData RegisterClientData  `json:"RegisterClient"`
	DeviceAuth StartDeviceAuthData `json:"StartDeviceAuth"`
	Token      CreateTokenResponse `json:"TokenResponse"`
	accounts   []AccountInfo
	roles      []RoleInfo
}

func NewAWSSSO(region, ssoRegion, startUrl string, store *SecureStorage) *AWSSSO {
	mySession := session.Must(session.NewSession())
	oidcSession := ssooidc.New(mySession, aws.NewConfig().WithRegion(region))
	ssoSession := sso.New(mySession, aws.NewConfig().WithRegion(region))

	as := AWSSSO{
		sso:        *ssoSession,
		ssooidc:    *oidcSession,
		store:      *store,
		ClientName: awsSSOClientName,
		ClientType: awsSSOClientType,
		SsoRegion:  ssoRegion,
		StartUrl:   startUrl,
	}
	return &as
}

func (as *AWSSSO) storeKey() string {
	return fmt.Sprintf("%s:%s", as.SsoRegion, as.StartUrl)
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

// this struct should be cached for long term if possible
type RegisterClientData struct {
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	ClientId              string `json:"clientId"`
	ClientIdIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
}

// Does the needful to talk to AWS or read our cache to get the RegisterClientData
func (as *AWSSSO) RegisterClient() error {
	err := as.store.GetRegisterClientData(as.storeKey(), &as.ClientData)
	// XXX: I think an hour buffer here is fine?
	if err == nil && as.ClientData.ClientSecretExpiresAt > time.Now().Add(time.Hour).Unix() {
		log.Info("Using RegisterClient cache")
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

	as.ClientData = RegisterClientData{
		// AuthorizationEndpoint: *resp.AuthorizationEndpoint,
		ClientId:              aws.StringValue(resp.ClientId),
		ClientSecret:          aws.StringValue(resp.ClientSecret),
		ClientIdIssuedAt:      aws.Int64Value(resp.ClientIdIssuedAt),
		ClientSecretExpiresAt: aws.Int64Value(resp.ClientSecretExpiresAt),
		// TokenEndpoint:         *resp.TokenEndpoint,
	}
	err = as.store.SaveRegisterClientData(as.storeKey(), as.ClientData)
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
		StartUrl:     aws.String(as.StartUrl),
		ClientId:     aws.String(as.ClientData.ClientId),
		ClientSecret: aws.String(as.ClientData.ClientSecret),
	}
	resp, err := as.ssooidc.StartDeviceAuthorization(&input)
	if err != nil {
		return err
	}

	as.DeviceAuth = StartDeviceAuthData{
		DeviceCode:              aws.StringValue(resp.DeviceCode),
		UserCode:                aws.StringValue(resp.UserCode),
		VerificationUri:         aws.StringValue(resp.VerificationUri),
		VerificationUriComplete: aws.StringValue(resp.VerificationUriComplete),
		ExpiresIn:               aws.Int64Value(resp.ExpiresIn),
		Interval:                aws.Int64Value(resp.Interval),
	}
	log.Infof("Created OIDC device code for %s (expires in: %ds)",
		as.StartUrl, as.DeviceAuth.ExpiresIn)

	return nil
}

type DeviceAuthInfo struct {
	VerificationUri         string
	VerificationUriComplete string
	UserCode                string
}

func (da *DeviceAuthInfo) OpenBrowser() error {
	log.Infof("Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n",
		da.VerificationUriComplete)

	if err := open.Run(da.VerificationUriComplete); err != nil {
		return err
	}
	return nil
}

func (as *AWSSSO) GetDeviceAuthInfo() (DeviceAuthInfo, error) {
	if as.DeviceAuth.VerificationUri == "" {
		return DeviceAuthInfo{}, fmt.Errorf("No valid verification url is available")
	}

	info := DeviceAuthInfo{
		VerificationUri:         as.DeviceAuth.VerificationUri,
		VerificationUriComplete: as.DeviceAuth.VerificationUriComplete,
		UserCode:                as.DeviceAuth.UserCode,
	}
	return info, nil
}

type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"` // should be cached to issue new creds
	ExpiresIn    int64  `json:"expiresIn"`   // number of seconds it expires in (from AWS)
	ExpiresAt    int64  `json:"expiresAt"`   // Unix time when it expires
	IdToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"tokenType"`
}

// Blocks until we have a token
func (as *AWSSSO) CreateToken() error {
	err := as.store.GetCreateTokenResponse(as.storeKey(), &as.Token)
	// XXX: I think an hour buffer here is fine?
	if err == nil && as.ClientData.ClientSecretExpiresAt > time.Now().Add(time.Hour).Unix() {
		log.Info("Using CreateToken cache")
		return nil
	}

	input := ssooidc.CreateTokenInput{
		ClientId:     aws.String(as.ClientData.ClientId),
		ClientSecret: aws.String(as.ClientData.ClientSecret),
		DeviceCode:   aws.String(as.DeviceAuth.DeviceCode),
		GrantType:    aws.String(awsSSOGrantType),
	}

	// figure out our timings
	var slowDown = SLOW_DOWN_SEC * time.Second
	var retryInterval = RETRY_INTERVAL * time.Second
	if as.DeviceAuth.Interval > 0 {
		retryInterval = time.Duration(as.DeviceAuth.Interval) * time.Second
	}

	var resp *ssooidc.CreateTokenOutput

	for {
		resp, err = as.ssooidc.CreateToken(&input)
		if err == nil {
			break
		}

		e, ok := err.(awserr.Error)
		if !ok {
			return err
		}

		switch e.Code() {
		case ssooidc.ErrCodeSlowDownException:
			log.Debugf("Slowing down CreateToken()")
			retryInterval += slowDown
			fallthrough

		case ssooidc.ErrCodeAuthorizationPendingException:
			time.Sleep(retryInterval)
			continue

		default:
			return err
		}
	}

	secs, _ := time.ParseDuration(fmt.Sprintf("%ds", *resp.ExpiresIn))
	as.Token = CreateTokenResponse{
		AccessToken:  aws.StringValue(resp.AccessToken),
		ExpiresIn:    aws.Int64Value(resp.ExpiresIn),
		ExpiresAt:    time.Now().Add(secs).Unix(),
		IdToken:      aws.StringValue(resp.IdToken),
		RefreshToken: aws.StringValue(resp.RefreshToken), // per AWS docs, not currently implimented
		TokenType:    aws.StringValue(resp.TokenType),
	}
	err = as.store.SaveCreateTokenResponse(as.storeKey(), as.Token)
	if err != nil {
		log.WithError(err).Errorf("Unable to save CreateTokenResponse")
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

type RoleInfo struct {
	Idx       int    `header:"Id"`
	AccountId string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	RoleName  string `yaml:"RoleName" json:"RoleName" header:"RoleName"`
}

func (ri RoleInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ri)
	return utils.GetHeaderTag(v, fieldName)
}

func (as *AWSSSO) GetRoles(accountId string) ([]RoleInfo, error) {
	if len(as.roles) > 0 {
		return as.roles, nil
	}

	input := sso.ListAccountRolesInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(accountId),
		MaxResults:  aws.Int64(1000),
	}
	output, err := as.sso.ListAccountRoles(&input)
	if err != nil {
		return as.roles, err
	}
	for i, r := range output.RoleList {
		as.roles = append(as.roles, RoleInfo{
			Idx:       i,
			AccountId: aws.StringValue(r.AccountId),
			RoleName:  aws.StringValue(r.RoleName),
		})
	}
	for *output.NextToken != "" {
		input.NextToken = output.NextToken
		output, err := as.sso.ListAccountRoles(&input)
		if err != nil {
			return as.roles, err
		}
		x := len(as.roles)
		for i, r := range output.RoleList {
			as.roles = append(as.roles, RoleInfo{
				Idx:       x + i,
				AccountId: aws.StringValue(r.AccountId),
				RoleName:  aws.StringValue(r.RoleName),
			})
		}
	}
	return as.roles, nil
}

type AccountInfo struct {
	Idx          int    `header:"Id"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
}

func (ai AccountInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ai)
	return utils.GetHeaderTag(v, fieldName)
}

func (as *AWSSSO) GetAccounts() ([]AccountInfo, error) {
	if len(as.accounts) > 0 {
		return as.accounts, nil
	}

	input := sso.ListAccountsInput{
		AccessToken: aws.String(as.Token.AccessToken),
		MaxResults:  aws.Int64(1000),
	}
	output, err := as.sso.ListAccounts(&input)
	if err != nil {
		return as.accounts, err
	}
	for i, r := range output.AccountList {
		as.accounts = append(as.accounts, AccountInfo{
			Idx:          i,
			AccountId:    aws.StringValue(r.AccountId),
			AccountName:  aws.StringValue(r.AccountName),
			EmailAddress: aws.StringValue(r.EmailAddress),
		})
	}
	for aws.StringValue(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err := as.sso.ListAccounts(&input)
		if err != nil {
			return as.accounts, err
		}
		x := len(as.accounts)
		for i, r := range output.AccountList {
			as.accounts = append(as.accounts, AccountInfo{
				Idx:          x + i,
				AccountId:    aws.StringValue(r.AccountId),
				AccountName:  aws.StringValue(r.AccountName),
				EmailAddress: aws.StringValue(r.EmailAddress),
			})
		}
	}
	return as.accounts, nil

}
