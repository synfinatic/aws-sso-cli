package sso

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
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
	"github.com/synfinatic/gotable"
)

type AWSSSO struct {
	sso        sso.SSO
	ssooidc    ssooidc.SSOOIDC
	store      SecureStorage
	ClientName string                `json:"ClientName"`
	ClientType string                `json:"ClientType"`
	SsoRegion  string                `json:"ssoRegion"`
	StartUrl   string                `json:"startUrl"`
	ClientData RegisterClientData    `json:"RegisterClient"`
	DeviceAuth StartDeviceAuthData   `json:"StartDeviceAuth"`
	Token      CreateTokenResponse   `json:"TokenResponse"`
	Accounts   []AccountInfo         `json:"Accounts"`
	Roles      map[string][]RoleInfo `json:"Roles"`
}

func NewAWSSSO(ssoRegion, startUrl string, store *SecureStorage) *AWSSSO {
	mySession := session.Must(session.NewSession())
	oidcSession := ssooidc.New(mySession, aws.NewConfig().WithRegion(ssoRegion))
	ssoSession := sso.New(mySession, aws.NewConfig().WithRegion(ssoRegion))

	as := AWSSSO{
		sso:        *ssoSession,
		ssooidc:    *oidcSession,
		store:      *store,
		ClientName: awsSSOClientName,
		ClientType: awsSSOClientType,
		SsoRegion:  ssoRegion,
		StartUrl:   startUrl,
		Roles:      map[string][]RoleInfo{},
	}
	return &as
}

func (as *AWSSSO) StoreKey() string {
	return fmt.Sprintf("%s|%s", as.SsoRegion, as.StartUrl)
}

func (as *AWSSSO) Authenticate(urlAction, browser string) error {
	// see if we have valid cached data
	token := CreateTokenResponse{}
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &token)
	if err == nil && !token.Expired() {
		as.Token = token
		return nil
	} else if err != nil {
		log.WithError(err).Errorf("Unable to use cache")
	} else {
		if as.Token.ExpiresAt != 0 {
			t := time.Unix(as.Token.ExpiresAt, 0)
			log.Infof("Token expired at: %s", t.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
		} else {
			log.Info("Token has expired.  Refreshing...")
		}
	}

	// Nope- fall back to our standard process
	err = as.RegisterClient()
	if err != nil {
		return fmt.Errorf("Unable to RegisterClient: %s", err.Error())
	}

	err = as.StartDeviceAuthorization()
	if err != nil {
		return fmt.Errorf("Unable to StartDeviceAuth: %s", err.Error())
	}

	auth, err := as.GetDeviceAuthInfo()
	if err != nil {
		return fmt.Errorf("Unable to get DeviceAuthInfo: %s", err.Error())
	}

	utils.HandleUrl(urlAction, browser, auth.VerificationUriComplete,
		"Please open the following URL in your browser:\n\n", "\n\n")

	log.Infof("Waiting for SSO authentication...")

	err = as.CreateToken()
	if err != nil {
		return fmt.Errorf("Unable to get AWS SSO Token: %s", err.Error())
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

// this struct should be cached for long term if possible
type RegisterClientData struct {
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	ClientId              string `json:"clientId"`
	ClientIdIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
}

func (r *RegisterClientData) Expired() bool {
	// XXX: I think an hour buffer here is fine?
	if r.ClientSecretExpiresAt > time.Now().Add(time.Hour).Unix() {
		return false
	}
	return true
}

// Does the needful to talk to AWS or read our cache to get the RegisterClientData
func (as *AWSSSO) RegisterClient() error {
	err := as.store.GetRegisterClientData(as.StoreKey(), &as.ClientData)
	if err == nil && !as.ClientData.Expired() {
		log.Debug("Using RegisterClient cache")
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
	err = as.store.SaveRegisterClientData(as.StoreKey(), as.ClientData)
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
	log.Debugf("Created OIDC device code for %s (expires in: %ds)",
		as.StartUrl, as.DeviceAuth.ExpiresIn)

	return nil
}

type DeviceAuthInfo struct {
	VerificationUri         string
	VerificationUriComplete string
	UserCode                string
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

func (t *CreateTokenResponse) Expired() bool {
	// XXX: I think an minute buffer here is fine?
	if t.ExpiresAt > time.Now().Add(time.Minute).Unix() {
		return false
	}
	return true
}

// Blocks until we have a token
func (as *AWSSSO) CreateToken() error {
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &as.Token)
	if err == nil && !as.Token.Expired() {
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
	err = as.store.SaveCreateTokenResponse(as.StoreKey(), as.Token)
	if err != nil {
		log.WithError(err).Errorf("Unable to save CreateTokenResponse")
	}

	return nil
}

type RoleInfo struct {
	Id           int    `yaml:"Id" json:"Id" header:"Id"`
	Arn          string `yaml:"-" json:"-" header:"Arn"`
	RoleName     string `yaml:"RoleName" json:"RoleName" header:"RoleName"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
	Expires      int64  `yaml:"Expires" json:"Expires" header:"Expires"`
	Profile      string `yaml:"Profile" json:"Profile" header:"Profile"`
	Region       string `yaml:"Region" json:"Region" header:"Region"`
	SSORegion    string `header:"SSORegion"`
	StartUrl     string `header:"StartUrl"`
}

func (ri RoleInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ri)
	return gotable.GetHeaderTag(v, fieldName)
}

func (ri RoleInfo) RoleArn() string {
	return fmt.Sprintf("arn:aws:iam:%s:role/%s", ri.AccountId, ri.RoleName)
}

func (as *AWSSSO) GetRoles(account AccountInfo) ([]RoleInfo, error) {
	roles, ok := as.Roles[account.AccountId]
	if ok && len(roles) > 0 {
		return roles, nil
	}
	as.Roles[account.AccountId] = []RoleInfo{}

	input := sso.ListAccountRolesInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(account.AccountId),
		MaxResults:  aws.Int64(1000),
	}
	output, err := as.sso.ListAccountRoles(&input)
	if err != nil {
		return as.Roles[account.AccountId], err
	}
	for i, r := range output.RoleList {
		as.Roles[account.AccountId] = append(as.Roles[account.AccountId], RoleInfo{
			Id:           i,
			AccountId:    aws.StringValue(r.AccountId),
			RoleName:     aws.StringValue(r.RoleName),
			AccountName:  account.AccountName,
			EmailAddress: account.EmailAddress,
			SSORegion:    as.SsoRegion,
			StartUrl:     as.StartUrl,
		})
	}
	for aws.StringValue(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err := as.sso.ListAccountRoles(&input)
		if err != nil {
			return as.Roles[account.AccountId], err
		}
		x := len(as.Roles)
		for i, r := range output.RoleList {
			as.Roles[account.AccountId] = append(as.Roles[account.AccountId], RoleInfo{
				Id:           x + i,
				AccountId:    aws.StringValue(r.AccountId),
				RoleName:     aws.StringValue(r.RoleName),
				AccountName:  account.AccountName,
				EmailAddress: account.EmailAddress,
			})
		}
	}
	return as.Roles[account.AccountId], nil
}

type AccountInfo struct {
	Id           int    `yaml:"Id" json:"Id" header:"Id"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
}

func (ai AccountInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ai)
	return gotable.GetHeaderTag(v, fieldName)
}

func (ai AccountInfo) GetAccountId64() int64 {
	i64, err := strconv.ParseInt(ai.AccountId, 10, 64)
	if err != nil {
		log.WithError(err).Fatalf("Invalid AWS AccountID from AWS SSO: %s", ai.AccountId)
	}
	return i64
}

func (as *AWSSSO) GetAccounts() ([]AccountInfo, error) {
	if len(as.Accounts) > 0 {
		return as.Accounts, nil
	}

	input := sso.ListAccountsInput{
		AccessToken: aws.String(as.Token.AccessToken),
		MaxResults:  aws.Int64(1000),
	}
	output, err := as.sso.ListAccounts(&input)
	if err != nil {
		return as.Accounts, err
	}
	for i, r := range output.AccountList {
		as.Accounts = append(as.Accounts, AccountInfo{
			Id:           i,
			AccountId:    aws.StringValue(r.AccountId),
			AccountName:  aws.StringValue(r.AccountName),
			EmailAddress: aws.StringValue(r.EmailAddress),
		})
	}
	for aws.StringValue(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err := as.sso.ListAccounts(&input)
		if err != nil {
			return as.Accounts, err
		}
		x := len(as.Accounts)
		for i, r := range output.AccountList {
			as.Accounts = append(as.Accounts, AccountInfo{
				Id:           x + i,
				AccountId:    aws.StringValue(r.AccountId),
				AccountName:  aws.StringValue(r.AccountName),
				EmailAddress: aws.StringValue(r.EmailAddress),
			})
		}
	}
	return as.Accounts, nil

}

type RoleCredentials struct { // Cache
	RoleName        string `json:"roleName"`
	AccountId       int64  `json:"accountId"`
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      int64  `json:"expiration"` // not in seconds!
}

func (r *RoleCredentials) RoleArn() string {
	return fmt.Sprintf("arn:aws:iam:%d:role/%s", r.AccountId, r.RoleName)
}

func (r *RoleCredentials) ExpireString() string {
	// apparently Expiration is in ms???
	return time.Unix(r.Expiration/1000, 0).String()
}

// AccountIdStr returns our AccountId as a string
func (r *RoleCredentials) AccountIdStr() string {
	return strconv.FormatInt(r.AccountId, 10)
}

func (as *AWSSSO) GetRoleCredentials(accountId int64, role string) (RoleCredentials, error) {
	aId := strconv.FormatInt(accountId, 10)

	input := sso.GetRoleCredentialsInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(aId),
		RoleName:    aws.String(role),
	}
	output, err := as.sso.GetRoleCredentials(&input)
	if err != nil {
		return RoleCredentials{}, err
	}

	ret := RoleCredentials{
		AccountId:       accountId,
		RoleName:        role,
		AccessKeyId:     aws.StringValue(output.RoleCredentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(output.RoleCredentials.SecretAccessKey),
		SessionToken:    aws.StringValue(output.RoleCredentials.SessionToken),
		Expiration:      aws.Int64Value(output.RoleCredentials.Expiration),
	}
	return ret, nil
}

// returns all of the available tags from AWS SSO
func (as *AWSSSO) GetAllTags() *TagsList {
	tags := NewTagsList()
	accounts, err := as.GetAccounts()
	if err != nil {
		log.Fatalf("Unable to get accounts: %s", err.Error())
	}

	for _, aInfo := range accounts {
		roles, err := as.GetRoles(aInfo)
		if err != nil {
			log.Fatalf("Unable to get roles: %s", err.Error())
		}

		for _, role := range roles {
			tags.Add("RoleName", role.RoleName)
			tags.Add("AccountId", role.AccountId)
			tags.Add("AccountName", role.AccountName)
			tags.Add("EmailAddress", role.EmailAddress)
		}
	}
	return tags
}
