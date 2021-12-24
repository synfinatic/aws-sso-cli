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
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
	"github.com/synfinatic/gotable"
)

type AWSSSO struct {
	sso        sso.SSO
	ssooidc    ssooidc.SSOOIDC
	store      storage.SecureStorage
	ClientName string                      `json:"ClientName"`
	ClientType string                      `json:"ClientType"`
	SsoRegion  string                      `json:"ssoRegion"`
	StartUrl   string                      `json:"startUrl"`
	ClientData storage.RegisterClientData  `json:"RegisterClient"`
	DeviceAuth storage.StartDeviceAuthData `json:"StartDeviceAuth"`
	Token      storage.CreateTokenResponse `json:"TokenResponse"`
	Accounts   []AccountInfo               `json:"Accounts"`
	Roles      map[string][]RoleInfo       `json:"Roles"`
	SSOConfig  *SSOConfig                  `json:"SSOConfig"`
}

func NewAWSSSO(s *SSOConfig, store *storage.SecureStorage) *AWSSSO {
	mySession := session.Must(session.NewSession())
	oidcSession := ssooidc.New(mySession, aws.NewConfig().WithRegion(s.SSORegion))
	ssoSession := sso.New(mySession, aws.NewConfig().WithRegion(s.SSORegion))

	as := AWSSSO{
		sso:        *ssoSession,
		ssooidc:    *oidcSession,
		store:      *store,
		ClientName: awsSSOClientName,
		ClientType: awsSSOClientType,
		SsoRegion:  s.SSORegion,
		StartUrl:   s.StartUrl,
		Roles:      map[string][]RoleInfo{},
		SSOConfig:  s,
	}
	return &as
}

func (as *AWSSSO) StoreKey() string {
	return fmt.Sprintf("%s|%s", as.SsoRegion, as.StartUrl)
}

func (as *AWSSSO) Authenticate(urlAction, browser string) error {
	// see if we have valid cached data
	token := storage.CreateTokenResponse{}
	err := as.store.GetCreateTokenResponse(as.StoreKey(), &token)
	if err == nil && !token.Expired() {
		as.Token = token
		return nil
	} else if err != nil {
		log.WithError(err).Errorf("Unable read SSO token from cache")
	} else {
		if as.Token.ExpiresAt != 0 {
			t := time.Unix(as.Token.ExpiresAt, 0)
			log.Infof("Cached SSO token expired at: %s.  Reauthenticating...\n", t.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
		} else {
			log.Infof("Cached SSO token has expired.  Reauthenticating...\n")
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

	err = utils.HandleUrl(urlAction, browser, auth.VerificationUriComplete,
		"Please open the following URL in your browser:\n\n", "\n\n")
	if err != nil {
		return err
	}

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

// Does the needful to talk to AWS or read our cache to get the RegisterClientData
func (as *AWSSSO) RegisterClient() error {
	log.Tracef("RegisterClient()")
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

	as.ClientData = storage.RegisterClientData{
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

// Makes the call to AWS to initiate the OIDC auth to the SSO provider.
func (as *AWSSSO) StartDeviceAuthorization() error {
	log.Tracef("StartDeviceAuthorization()")
	input := ssooidc.StartDeviceAuthorizationInput{
		StartUrl:     aws.String(as.StartUrl),
		ClientId:     aws.String(as.ClientData.ClientId),
		ClientSecret: aws.String(as.ClientData.ClientSecret),
	}
	resp, err := as.ssooidc.StartDeviceAuthorization(&input)
	if err != nil {
		return err
	}

	as.DeviceAuth = storage.StartDeviceAuthData{
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
	log.Tracef("GetDeviceAuthInfo()")
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

// Blocks until we have a token
func (as *AWSSSO) CreateToken() error {
	log.Tracef("CreateToken()")
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
	as.Token = storage.CreateTokenResponse{
		AccessToken:  aws.StringValue(resp.AccessToken),
		ExpiresIn:    aws.Int64Value(resp.ExpiresIn),
		ExpiresAt:    time.Now().Add(secs).Unix(),
		IdToken:      aws.StringValue(resp.IdToken),
		RefreshToken: aws.StringValue(resp.RefreshToken), // per AWS docs, not currently implemented
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
	Via          string `header:"Via"`
}

func (ri RoleInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ri)
	return gotable.GetHeaderTag(v, fieldName)
}

func (ri RoleInfo) RoleArn() string {
	a, _ := strconv.ParseInt(ri.AccountId, 10, 64)
	return utils.MakeRoleARN(a, ri.RoleName)
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
		var via string

		aId, err := strconv.ParseInt(account.AccountId, 10, 64)
		if err != nil {
			return as.Roles[account.AccountId], fmt.Errorf("Unable to parse accountid %s: %s",
				account.AccountId, err.Error())
		}
		ssoRole, err := as.SSOConfig.GetRole(aId, aws.StringValue(r.RoleName))
		if err != nil && len(ssoRole.Via) > 0 {
			via = ssoRole.Via
		}
		as.Roles[account.AccountId] = append(as.Roles[account.AccountId], RoleInfo{
			Id:           i,
			AccountId:    aws.StringValue(r.AccountId),
			RoleName:     aws.StringValue(r.RoleName),
			AccountName:  account.AccountName,
			EmailAddress: account.EmailAddress,
			SSORegion:    as.SsoRegion,
			StartUrl:     as.StartUrl,
			Via:          via,
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

// GetRoleCredentials recursively does any sts:AssumeRole calls as necessary for role-chaining
// through `Via` and returns the final set of RoleCredentials for the requested role
func (as *AWSSSO) GetRoleCredentials(accountId int64, role string) (storage.RoleCredentials, error) {
	aId, err := utils.AccountIdToString(accountId)
	if err != nil {
		return storage.RoleCredentials{}, err
	}

	configRole, err := as.SSOConfig.GetRole(accountId, role)
	if err != nil && configRole.Via == "" {
		log.Debugf("Getting %s:%s directly", aId, role)
		// This are the actual role creds requested through AWS SSO
		input := sso.GetRoleCredentialsInput{
			AccessToken: aws.String(as.Token.AccessToken),
			AccountId:   aws.String(aId),
			RoleName:    aws.String(role),
		}
		output, err := as.sso.GetRoleCredentials(&input)
		if err != nil {
			return storage.RoleCredentials{}, err
		}

		ret := storage.RoleCredentials{
			AccountId:       accountId,
			RoleName:        role,
			AccessKeyId:     aws.StringValue(output.RoleCredentials.AccessKeyId),
			SecretAccessKey: aws.StringValue(output.RoleCredentials.SecretAccessKey),
			SessionToken:    aws.StringValue(output.RoleCredentials.SessionToken),
			Expiration:      aws.Int64Value(output.RoleCredentials.Expiration),
		}

		return ret, nil
	}

	// Need to recursively call sts:AssumeRole in order to retrieve the STS creds for
	// the requested role
	// role has a Via
	log.Debugf("Getting %s:%s via %s", aId, role, configRole.Via)
	viaAccountId, viaRole, err := utils.ParseRoleARN(configRole.Via)
	if err != nil {
		return storage.RoleCredentials{}, fmt.Errorf("Invalid Via %s: %s", configRole.Via, err.Error())
	}

	// recurse
	creds, err := as.GetRoleCredentials(viaAccountId, viaRole)
	if err != nil {
		return storage.RoleCredentials{}, err
	}

	sessionCreds := credentials.NewStaticCredentials(
		creds.AccessKeyId,
		creds.SecretAccessKey,
		creds.SessionToken,
	)
	mySession := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(as.SsoRegion),
			Credentials: sessionCreds,
		},
	}))
	stsSession := sts.New(mySession)

	input := sts.AssumeRoleInput{
		//		DurationSeconds: aws.Int64(900),
		RoleArn:         aws.String(utils.MakeRoleARN(accountId, role)),
		RoleSessionName: aws.String(fmt.Sprintf("Via_%s_%s", aId, role)),
	}
	if configRole.ExternalId != "" {
		// Optional vlaue: https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#AssumeRoleInput
		input.ExternalId = aws.String(configRole.ExternalId)
	}
	if configRole.SourceIdentity != "" {
		input.SourceIdentity = aws.String(configRole.SourceIdentity)
	}

	output, err := stsSession.AssumeRole(&input)
	if err != nil {
		return storage.RoleCredentials{}, err
	}
	log.Debugf("%s", spew.Sdump(output))
	ret := storage.RoleCredentials{
		AccountId:       accountId,
		RoleName:        role,
		AccessKeyId:     aws.StringValue(output.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(output.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(output.Credentials.SessionToken),
		Expiration:      aws.TimeValue(output.Credentials.Expiration).Unix(),
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
