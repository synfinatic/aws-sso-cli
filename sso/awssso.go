package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"reflect"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
	"github.com/synfinatic/gotable"
)

// Necessary for mocking
type SsoOidcApi interface {
	RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

type SsoApi interface {
	ListAccountRoles(context.Context, *sso.ListAccountRolesInput, ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error)
	ListAccounts(context.Context, *sso.ListAccountsInput, ...func(*sso.Options)) (*sso.ListAccountsOutput, error)
	GetRoleCredentials(context.Context, *sso.GetRoleCredentialsInput, ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error)
}

type AWSSSO struct {
	sso        SsoApi
	ssooidc    SsoOidcApi
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
	urlAction  string                      // cache for future calls
	browser    string                      // cache for future calls
}

func NewAWSSSO(s *SSOConfig, store *storage.SecureStorage) *AWSSSO {
	oidcSession := ssooidc.New(ssooidc.Options{
		Region: s.SSORegion,
	})

	ssoSession := sso.New(sso.Options{
		Region: s.SSORegion,
	})

	as := AWSSSO{
		sso:        ssoSession,
		ssooidc:    oidcSession,
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
		MaxResults:  aws.Int32(1000),
	}
	output, err := as.sso.ListAccountRoles(context.TODO(), &input)
	if err != nil {
		// sometimes our AccessToken is invalid even though it has not expired
		// so retry once
		log.Debugf("Unexpected AccessToken failure.  Refreshing...")
		if err = as.reauthenticate(); err != nil {
			// failed again... return our cache?
			return as.Roles[account.AccountId], err
		}
		input.AccessToken = aws.String(as.Token.AccessToken)
		if output, err = as.sso.ListAccountRoles(context.TODO(), &input); err != nil {
			return as.Roles[account.AccountId], err
		}
	}
	for i, r := range output.RoleList {
		if err := as.makeRoleInfo(account, i, r); err != nil {
			return as.Roles[account.AccountId], err
		}
	}

	for aws.ToString(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err = as.sso.ListAccountRoles(context.TODO(), &input)
		if err != nil {
			return as.Roles[account.AccountId], err
		}
		roleCount := len(as.Roles[account.AccountId])
		for i, r := range output.RoleList {
			x := roleCount + i
			if err := as.makeRoleInfo(account, x, r); err != nil {
				return as.Roles[account.AccountId], err
			}
		}
	}
	return as.Roles[account.AccountId], nil
}

// makeRoleInfo takes the sso.types.RoleInfo and adds it onto our as.Roles[accountId] list
func (as *AWSSSO) makeRoleInfo(account AccountInfo, i int, r types.RoleInfo) error {
	var via string

	aId, _ := strconv.ParseInt(account.AccountId, 10, 64)
	ssoRole, err := as.SSOConfig.GetRole(aId, aws.ToString(r.RoleName))
	if err != nil && len(ssoRole.Via) > 0 {
		via = ssoRole.Via
	}
	as.Roles[account.AccountId] = append(as.Roles[account.AccountId], RoleInfo{
		Id:           i,
		AccountId:    aws.ToString(r.AccountId),
		Arn:          utils.MakeRoleARN(aId, aws.ToString(r.RoleName)),
		RoleName:     aws.ToString(r.RoleName),
		AccountName:  account.AccountName,
		EmailAddress: account.EmailAddress,
		SSORegion:    as.SsoRegion,
		StartUrl:     as.StartUrl,
		Via:          via,
	})
	return nil
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
		log.WithError(err).Panicf("Invalid AWS AccountID from AWS SSO: %s", ai.AccountId)
	}
	if i64 < 0 {
		log.WithError(err).Panicf("AWS AccountID must be >= 0: %s", ai.AccountId)
	}
	return i64
}

func (as *AWSSSO) GetAccounts() ([]AccountInfo, error) {
	if len(as.Accounts) > 0 {
		return as.Accounts, nil
	}

	input := sso.ListAccountsInput{
		AccessToken: aws.String(as.Token.AccessToken),
		MaxResults:  aws.Int32(1000),
	}
	output, err := as.sso.ListAccounts(context.TODO(), &input)
	if err != nil {
		// sometimes our AccessToken is invalid so try a new one once?
		log.Debugf("Unexpected AccessToken failure.  Refreshing...")
		if err = as.reauthenticate(); err != nil {
			return as.Accounts, err
		}
		input.AccessToken = aws.String(as.Token.AccessToken)
		if output, err = as.sso.ListAccounts(context.TODO(), &input); err != nil {
			return as.Accounts, err
		}
	}
	for i, r := range output.AccountList {
		as.Accounts = append(as.Accounts, AccountInfo{
			Id:           i,
			AccountId:    aws.ToString(r.AccountId),
			AccountName:  aws.ToString(r.AccountName),
			EmailAddress: aws.ToString(r.EmailAddress),
		})
	}
	for aws.ToString(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err = as.sso.ListAccounts(context.TODO(), &input)
		if err != nil {
			return as.Accounts, err
		}
		x := len(as.Accounts)
		for i, r := range output.AccountList {
			as.Accounts = append(as.Accounts, AccountInfo{
				Id:           x + i,
				AccountId:    aws.ToString(r.AccountId),
				AccountName:  aws.ToString(r.AccountName),
				EmailAddress: aws.ToString(r.EmailAddress),
			})
		}
	}

	return as.Accounts, nil
}

var roleChainMap map[string]bool = map[string]bool{} // track our roles

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
		output, err := as.sso.GetRoleCredentials(context.TODO(), &input)
		if err != nil {
			return storage.RoleCredentials{}, err
		}

		ret := storage.RoleCredentials{
			AccountId:       accountId,
			RoleName:        role,
			AccessKeyId:     aws.ToString(output.RoleCredentials.AccessKeyId),
			SecretAccessKey: aws.ToString(output.RoleCredentials.SecretAccessKey),
			SessionToken:    aws.ToString(output.RoleCredentials.SessionToken),
			Expiration:      output.RoleCredentials.Expiration,
		}

		return ret, nil
	}

	// Detect loops
	roleChainMap[configRole.ARN] = true
	for k := range roleChainMap {
		if k == configRole.Via {
			log.Fatalf("Detected role chain loop!  Getting %s via %s", configRole.ARN, configRole.Via)
		}
		roleChainMap[k] = true
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

	cfgCreds := credentials.NewStaticCredentialsProvider(
		creds.AccessKeyId,
		creds.SecretAccessKey,
		creds.SessionToken,
	)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(as.SsoRegion),
		config.WithCredentialsProvider(cfgCreds),
	)
	if err != nil {
		return storage.RoleCredentials{}, err
	}
	stsSession := sts.NewFromConfig(cfg)

	previousAccount, _ := utils.AccountIdToString(creds.AccountId)
	previousRole := fmt.Sprintf("%s@%s", creds.RoleName, previousAccount)

	input := sts.AssumeRoleInput{
		//		DurationSeconds: aws.Int64(900),
		RoleArn:         aws.String(utils.MakeRoleARN(accountId, role)),
		RoleSessionName: aws.String(previousRole),
	}
	if configRole.ExternalId != "" {
		// Optional vlaue: https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#AssumeRoleInput
		input.ExternalId = aws.String(configRole.ExternalId)
	}
	if configRole.SourceIdentity != "" {
		input.SourceIdentity = aws.String(configRole.SourceIdentity)
	}

	output, err := stsSession.AssumeRole(context.TODO(), &input)
	if err != nil {
		return storage.RoleCredentials{}, err
	}
	log.Debugf("%s", spew.Sdump(output))
	ret := storage.RoleCredentials{
		AccountId:       accountId,
		RoleName:        role,
		AccessKeyId:     aws.ToString(output.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(output.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(output.Credentials.SessionToken),
		Expiration:      aws.ToTime(output.Credentials.Expiration).UnixMilli(),
	}
	return ret, nil
}
