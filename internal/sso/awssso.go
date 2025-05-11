package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/gotable"
)

var MAX_RETRY_ATTEMPTS int = 10
var MAX_BACKOFF_SECONDS int = 5

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
	Logout(context.Context, *sso.LogoutInput, ...func(*sso.Options)) (*sso.LogoutOutput, error)
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

func NewAWSSSO(s *SSOConfig, store storage.SecureStorage) *AWSSSO {
	var maxRetry = MAX_RETRY_ATTEMPTS
	if s.MaxRetry > 0 {
		maxRetry = s.MaxRetry
	}
	var maxBackoff = MAX_BACKOFF_SECONDS
	if s.MaxBackoff > 0 {
		maxBackoff = s.MaxBackoff
	}
	log.Debug("loading SSO", "retries", maxRetry, "maxBackoff", maxBackoff)

	r := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = maxRetry
		o.MaxBackoff = time.Duration(maxBackoff) * time.Second
	})

	oidcSession := ssooidc.New(ssooidc.Options{
		Region:  s.SSORegion,
		Retryer: r,
	})

	ssoSession := sso.New(sso.Options{
		Region:  s.SSORegion,
		Retryer: r,
	})

	as := AWSSSO{
		key:            s.key,
		sso:            ssoSession,
		ssooidc:        oidcSession,
		store:          store,
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
		panic(fmt.Sprintf("Invalid AWS AccountID from AWS SSO: %s", ri.AccountId))
	}
	if i64 < 0 {
		panic(fmt.Sprintf("AWS AccountID must be >= 0: %s", ri.AccountId))
	}
	return i64
}

// GetRoles fetches all the AWS SSO IAM Roles for the given AWS Account
// Code is running up to X Threads via cache.processSSORoles()
// and we must stricly protect reads & writes to our as.Roles[] dict
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

	// must lock this becacase the access token can change
	as.tokenLock.Lock()
	input := sso.ListAccountRolesInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(account.AccountId),
		MaxResults:  aws.Int32(1000),
	}
	as.tokenLock.Unlock()

	output, err := as.ListAccountRoles(&input)
	if err != nil {
		// failed... give up
		as.rolesLock.RLock()
		defer as.rolesLock.RUnlock()
		return as.Roles[account.AccountId], err
	}

	// Process the output
	for i, r := range output.RoleList {
		as.makeRoleInfo(account, i, r)
	}

	for aws.ToString(output.NextToken) != "" {
		input.NextToken = output.NextToken
		output, err = as.ListAccountRoles(&input)
		if err != nil {
			// failed... give up
			as.rolesLock.RLock()
			defer as.rolesLock.RUnlock()
			return as.Roles[account.AccountId], err
		}

		as.rolesLock.RLock()
		roleCount := len(as.Roles[account.AccountId])
		as.rolesLock.RUnlock()

		for i, r := range output.RoleList {
			x := roleCount + i
			as.makeRoleInfo(account, x, r)
		}
	}
	as.rolesLock.RLock()
	defer as.rolesLock.RUnlock()
	return as.Roles[account.AccountId], nil
}

func (as *AWSSSO) ListAccounts(input *sso.ListAccountsInput) (*sso.ListAccountsOutput, error) {
	var err = errors.New("foo")
	var output *sso.ListAccountsOutput

	for cnt := 0; err != nil && cnt <= MAX_RETRY_ATTEMPTS; cnt++ {
		output, err = as.sso.ListAccounts(context.TODO(), input)
		if err != nil {
			var tmr *ssotypes.TooManyRequestsException
			var ue *ssotypes.UnauthorizedException
			switch {
			case errors.As(err, &ue):
				// sometimes our AccessToken is invalid so try a new one once?
				// if we have to re-auth, hold everyone else up since that will reduce other failures
				as.rolesLock.Lock()
				log.Error("AccessToken Unauthorized Error; refreshing", "error", err.Error())

				if err2 := as.reauthenticate(); err2 != nil {
					// fail hard now
					return output, err2
				}
				input.AccessToken = aws.String(as.Token.AccessToken)
				as.rolesLock.Unlock()
			case errors.As(err, &tmr):
				// try again
				log.Warn("Exceeded MaxRetry/MaxBackoff.  Consider tuning values.")
				time.Sleep(time.Duration(MAX_BACKOFF_SECONDS) * time.Second)

			default:
				log.Error("Unexpected error", "error", err.Error())
			}
		}
	}
	return output, err
}

// ListAccountRoles is a wrapper around sso.ListAccountRoles which does our retry logic
func (as *AWSSSO) ListAccountRoles(input *sso.ListAccountRolesInput) (*sso.ListAccountRolesOutput, error) {
	var err = errors.New("foo")
	var output *sso.ListAccountRolesOutput

	for cnt := 0; err != nil && cnt <= MAX_RETRY_ATTEMPTS; cnt++ {
		output, err = as.sso.ListAccountRoles(context.TODO(), input)

		if err != nil {
			var tmr *ssotypes.TooManyRequestsException
			var ue *ssotypes.UnauthorizedException
			switch {
			case errors.As(err, &ue):
				// sometimes our AccessToken is invalid so try a new one once?
				// if we have to re-auth, hold everyone else up since that will reduce other failures
				as.rolesLock.Lock()
				log.Error("AccessToken Unauthorized Error; refreshing", "error", err.Error())

				if err = as.reauthenticate(); err != nil {
					// fail hard now
					panic(fmt.Sprintf("Unexpected auth failure: %s", err.Error()))
				}
				input.AccessToken = aws.String(as.Token.AccessToken)
				as.rolesLock.Unlock()

			case errors.As(err, &tmr):
				// try again
				log.Warn("Exceeded MaxRetry/MaxBackoff.  Consider tuning values.")
				time.Sleep(time.Duration(MAX_BACKOFF_SECONDS) * time.Second)

			default:
				log.Error("Unexpected error", "error", err.Error())
			}
		}
	}
	return output, err
}

// makeRoleInfo takes the sso.types.RoleInfo and adds it onto our as.Roles[accountId] list
func (as *AWSSSO) makeRoleInfo(account AccountInfo, i int, r ssotypes.RoleInfo) {
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
		panic(fmt.Sprintf("Invalid AWS AccountID from AWS SSO: %s", ai.AccountId))
	}
	if i64 < 0 {
		panic(fmt.Sprintf("AWS AccountID must be >= 0: %s", ai.AccountId))
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
	output, err := as.ListAccounts(&input)
	if err != nil {
		return as.Accounts, err
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
		output, err = as.ListAccounts(&input)
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
		log.Debug("SSOConfig.GetRole()", "error", err.Error(), "config", as.SSOConfig)
	}

	// If not in config OR config does not require doing a Via
	if err != nil || configRole.Via == "" {
		log.Debug("Getting role directly", "accountID", aId, "role", role)
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
			panic(fmt.Sprintf("Detected role chain loop!  Getting %s via %s", configRole.ARN, configRole.Via))
		}
		roleChainMap[k] = true
	}

	// Need to recursively call sts:AssumeRole in order to retrieve the STS creds for
	// the requested role
	// role has a Via
	log.Debug("Calling AssumeRole", "role", fmt.Sprintf("%s:%s", aId, role), "via", configRole.Via)
	viaAccountId, viaRole, err := utils.ParseRoleARN(configRole.Via)
	if err != nil {
		return storage.RoleCredentials{}, fmt.Errorf("invalid Via %s: %s", configRole.Via, err.Error())
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
	log.Debug("stsSession.AssumeRole", "output", spew.Sdump(output))
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
