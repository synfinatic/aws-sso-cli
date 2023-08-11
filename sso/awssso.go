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
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/gotable"
)

const (
	MAX_RETRY_DELAY = 10.0
)

// Necessary for mocking
type SsoOidcAPI interface {
	RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

type SsoAPI interface {
	ListAccountRoles(context.Context, *sso.ListAccountRolesInput, ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error)
	ListAccounts(context.Context, *sso.ListAccountsInput, ...func(*sso.Options)) (*sso.ListAccountsOutput, error)
	GetRoleCredentials(context.Context, *sso.GetRoleCredentialsInput, ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error)
}

type AWSSSO struct {
	key              string // key in the settings file that names us
	sso              SsoAPI
	ssooidc          SsoOidcAPI
	store            storage.SecureStorage
	ClientName       string                      `json:"ClientName"`
	ClientType       string                      `json:"ClientType"`
	SsoRegion        string                      `json:"ssoRegion"`
	StartUrl         string                      `json:"startUrl"`
	ClientData       storage.RegisterClientData  `json:"RegisterClient"`
	DeviceAuth       storage.StartDeviceAuthData `json:"StartDeviceAuth"`
	Token            storage.CreateTokenResponse `json:"TokenResponse"`
	tokenLock        sync.RWMutex                // lock for our Token
	Accounts         []AccountInfo               `json:"Accounts"`
	Roles            map[string][]RoleInfo       `json:"Roles"` // key is AccountId
	rolesLock        sync.RWMutex                // lock for our Roles
	SSOConfig        *SSOConfig                  `json:"SSOConfig"`
	urlAction        url.Action                  // cache for future calls
	browser          string                      // cache for future calls
	urlExecCommand   []string                    // cache for future calls
	authenticateLock sync.RWMutex                // lock for reauthenticate()
}

func NewAWSSSO(s *SSOConfig, store *storage.SecureStorage) *AWSSSO {
	oidcSession := ssooidc.New(ssooidc.Options{
		Region:           s.SSORegion,
		RetryMaxAttempts: 5,
	})

	ssoSession := sso.New(sso.Options{
		Region:           s.SSORegion,
		RetryMaxAttempts: 5,
	})

	as := AWSSSO{
		key:            s.key,
		sso:            ssoSession,
		ssooidc:        oidcSession,
		store:          *store,
		ClientName:     awsSSOClientName,
		ClientType:     awsSSOClientType,
		SsoRegion:      s.SSORegion,
		StartUrl:       s.StartUrl,
		Roles:          map[string][]RoleInfo{}, // key is AccountId
		SSOConfig:      s,
		urlAction:      s.settings.UrlAction,
		browser:        s.settings.Browser,
		urlExecCommand: s.settings.UrlExecCommand,
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

func (ri RoleInfo) GetAccountId64() int64 {
	i64, err := strconv.ParseInt(ri.AccountId, 10, 64)
	if err != nil {
		log.WithError(err).Panicf("Invalid AWS AccountID from AWS SSO: %s", ri.AccountId)
	}
	if i64 < 0 {
		log.WithError(err).Panicf("AWS AccountID must be >= 0: %s", ri.AccountId)
	}
	return i64
}

// GetRoles fetches all the AWS SSO IAM Roles for the given AWS Account
// Code is running up to X Threads via cache.processSSORoles()
// and we must stricly protect our as.Roles[] dict
func (as *AWSSSO) GetRoles(account AccountInfo) ([]RoleInfo, error) {
	as.rolesLock.RLock()
	roles, ok := as.Roles[account.AccountId]
	as.rolesLock.RUnlock()
	if ok && len(roles) > 0 {
		return roles, nil
	}

	as.rolesLock.Lock()
	as.Roles[account.AccountId] = []RoleInfo{}
	as.rolesLock.Unlock()

	// why is this input value locked???
	as.tokenLock.RLock()
	input := sso.ListAccountRolesInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(account.AccountId),
		MaxResults:  aws.Int32(1000),
	}
	as.tokenLock.RUnlock()

	output := as.ListAccountRoles(&input)

	// Process the output
	for i, r := range output.RoleList {
		if err := as.makeRoleInfo(account, i, r); err != nil {
			// failed... give up
			as.rolesLock.RLock()
			defer as.rolesLock.RUnlock()
			return as.Roles[account.AccountId], err
		}
	}

	for aws.ToString(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output = as.ListAccountRoles(&input)

		as.rolesLock.RLock()
		roleCount := len(as.Roles[account.AccountId])
		as.rolesLock.RUnlock()

		for i, r := range output.RoleList {
			x := roleCount + i
			if err := as.makeRoleInfo(account, x, r); err != nil {
				as.rolesLock.RLock()
				defer as.rolesLock.RUnlock()
				return as.Roles[account.AccountId], err
			}
		}
	}
	as.rolesLock.RLock()
	defer as.rolesLock.RUnlock()
	return as.Roles[account.AccountId], nil
}

// ListAccountRoles is a wrapper around sso.ListAccountRoles which does our retry logic
func (as *AWSSSO) ListAccountRoles(input *sso.ListAccountRolesInput) *sso.ListAccountRolesOutput {
	output, err := as.sso.ListAccountRoles(context.TODO(), input)
	if err != nil {
		switch err.(type) {
		case *types.TooManyRequestsException:
			// 429 errors indicate we should wait and then try again
			sleepSec := rand.Float32() * MAX_RETRY_DELAY // #nosec sleep random amount up MAX_RETRY_DELAY nosec
			log.Errorf("TooManyRequestsException failure; trying again in %0.2f seconds...", sleepSec)
			time.Sleep(time.Duration(sleepSec) * time.Second)

		case *types.UnauthorizedException:
			// if we have to re-auth, keep hold everyone else up
			as.rolesLock.RLock()
			log.Errorf("AccessToken Unauthorized Error; refreshing: %s", err.Error())

			if err = as.reauthenticate(); err != nil {
				// failed hard
				log.WithError(err).Fatalf("Unexpected auth failure")
			}
			as.rolesLock.RUnlock()
			input.AccessToken = aws.String(as.Token.AccessToken)

		default:
			log.WithError(err).Fatalf("Unexpected error")
		}

		// retry the ListAccountRoles after doing our needful...
		if output, err = as.sso.ListAccountRoles(context.TODO(), input); err != nil {
			// failed again.  Give up.
			log.WithError(err).Fatalf("Unexpected error after retry")
		}
	}

	return output
}

// makeRoleInfo takes the sso.types.RoleInfo and adds it onto our as.Roles[accountId] list
func (as *AWSSSO) makeRoleInfo(account AccountInfo, i int, r types.RoleInfo) error {
	var via string

	aId, _ := strconv.ParseInt(account.AccountId, 10, 64)
	ssoRole, err := as.SSOConfig.GetRole(aId, aws.ToString(r.RoleName))
	if err != nil && len(ssoRole.Via) > 0 {
		via = ssoRole.Via
	}

	as.rolesLock.Lock()
	defer as.rolesLock.Unlock()
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

// GetAccounts queries AWS and returns a list of AWS accounts
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
		log.Errorf("Unexpected AccessToken failure; refreshing: %s", err)
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

	// is the role defined in the config file?
	configRole, err := as.SSOConfig.GetRole(accountId, role)
	if err != nil {
		log.Debugf("SSOConfig.GetRole(): %s", err.Error())
	}

	// If not in config OR config does not require doing a Via
	if err != nil || configRole.Via == "" {
		log.Debugf("Getting %s:%s directly", aId, role)
		// This is the actual role creds requested through AWS SSO
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
