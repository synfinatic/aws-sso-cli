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
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

var MAX_RETRY_ATTEMPTS int = 10
var MAX_BACKOFF_SECONDS int = 5

const (
	SSO_MAX_RESULTS = 100
)

type SsoAPI interface {
	ListAccountRoles(context.Context, *awssso.ListAccountRolesInput, ...func(*awssso.Options)) (*awssso.ListAccountRolesOutput, error)
	ListAccounts(context.Context, *awssso.ListAccountsInput, ...func(*awssso.Options)) (*awssso.ListAccountsOutput, error)
	GetRoleCredentials(context.Context, *awssso.GetRoleCredentialsInput, ...func(*awssso.Options)) (*awssso.GetRoleCredentialsOutput, error)
	Logout(context.Context, *awssso.LogoutInput, ...func(*awssso.Options)) (*awssso.LogoutOutput, error)
}

type AWSSSO struct {
	key              string // key in the settings file that names us
	sso              SsoAPI
	oidcClient       oidc.Client
	store            storage.SecureStorage
	stsEndpoint      string                          // non-empty overrides the STS endpoint (for integration tests only)
	ClientName       string                          `json:"ClientName"`
	ClientType       string                          `json:"ClientType"`
	SsoRegion        string                          `json:"ssoRegion"`
	StartUrl         string                          `json:"startUrl"`
	ClientData       storage.RegisterClientData      `json:"RegisterClient"`
	DeviceAuth       storage.StartDeviceAuthData     `json:"StartDeviceAuth"`
	Token            storage.CreateTokenResponse     `json:"TokenResponse"`
	tokenLock        sync.RWMutex                    // lock for our Token
	Accounts         []ssoconfig.AccountInfo         `json:"Accounts"`
	Roles            map[string][]ssoconfig.RoleInfo `json:"Roles"` // key is AccountId
	rolesLock        sync.RWMutex                    // lock for our Roles
	SSOConfig        *ssoconfig.SSOConfig            `json:"SSOConfig"`
	urlAction        uri.Action                      // cache for future calls
	browser          string                          // cache for future calls
	urlExecCommand   []string                        // cache for future calls
	authenticateLock sync.RWMutex                    // lock for reauthenticate()
}

func NewAWSSSO(s *ssoconfig.SSOConfig, store storage.SecureStorage) *AWSSSO {
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

	oidcSession := oidc.NewAWS(s.SSORegion, r)

	ssoSession := awssso.New(awssso.Options{
		Region:  s.SSORegion,
		Retryer: r,
	})

	as := AWSSSO{
		key:            s.GetKey(),
		sso:            ssoSession,
		oidcClient:     oidcSession,
		store:          store,
		ClientName:     awsSSOClientName,
		ClientType:     awsSSOClientType,
		SsoRegion:      s.SSORegion,
		StartUrl:       s.StartUrl,
		Roles:          map[string][]ssoconfig.RoleInfo{}, // key is AccountId
		SSOConfig:      s,
		urlAction:      s.UrlAction,
		browser:        s.Browser,
		urlExecCommand: s.UrlExecCommand,
	}
	return &as
}

// GetRoles fetches all the AWS SSO IAM Roles for the given AWS Account
// Code is running up to X Threads via cache.processSSORoles()
// and we must stricly protect reads & writes to our as.Roles[] dict
func (as *AWSSSO) GetRoles(account ssoconfig.AccountInfo) ([]ssoconfig.RoleInfo, error) {
	as.rolesLock.RLock()
	roles, ok := as.Roles[account.AccountId]
	as.rolesLock.RUnlock()
	if ok && len(roles) > 0 {
		return roles, nil
	}

	as.rolesLock.Lock()
	as.Roles[account.AccountId] = []ssoconfig.RoleInfo{}
	as.rolesLock.Unlock()

	// must lock this because the access token can change
	as.tokenLock.Lock()
	input := awssso.ListAccountRolesInput{
		AccessToken: aws.String(as.Token.AccessToken),
		AccountId:   aws.String(account.AccountId),
		MaxResults:  aws.Int32(SSO_MAX_RESULTS),
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

func (as *AWSSSO) ListAccounts(input *awssso.ListAccountsInput) (*awssso.ListAccountsOutput, error) {
	var err = errors.New("foo")
	var output *awssso.ListAccountsOutput

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
				log.Warn("AccessToken Unauthorized Error; forcing re-authentication")
				log.Debug("AccessToken Unauthorized Error; refreshing", "error", err.Error())

				if err2 := as.reauthenticate(context.Background()); err2 != nil {
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
func (as *AWSSSO) ListAccountRoles(input *awssso.ListAccountRolesInput) (*awssso.ListAccountRolesOutput, error) {
	var err = errors.New("foo")
	var output *awssso.ListAccountRolesOutput

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
				log.Warn("AccessToken Unauthorized Error; forcing re-authentication")
				log.Debug("AccessToken Unauthorized Error; refreshing", "error", err.Error())

				if err = as.reauthenticate(context.Background()); err != nil {
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
func (as *AWSSSO) makeRoleInfo(account ssoconfig.AccountInfo, i int, r ssotypes.RoleInfo) {
	var via string

	aId, _ := strconv.ParseInt(account.AccountId, 10, 64)
	ssoRole, err := as.SSOConfig.GetRole(aId, aws.ToString(r.RoleName))
	if err != nil && len(ssoRole.Via) > 0 {
		via = ssoRole.Via
	}

	as.rolesLock.Lock()
	defer as.rolesLock.Unlock()
	as.Roles[account.AccountId] = append(as.Roles[account.AccountId], ssoconfig.RoleInfo{
		Id:           i,
		AccountId:    aws.ToString(r.AccountId),
		Arn:          awsparse.MakeRoleARN(aId, aws.ToString(r.RoleName)),
		RoleName:     aws.ToString(r.RoleName),
		AccountName:  account.AccountName,
		EmailAddress: account.EmailAddress,
		SSORegion:    as.SsoRegion,
		StartUrl:     as.StartUrl,
		Via:          via,
	})
}

// GetAccounts queries AWS and returns a list of AWS accounts
func (as *AWSSSO) GetAccounts() ([]ssoconfig.AccountInfo, error) {
	if len(as.Accounts) > 0 {
		return as.Accounts, nil
	}

	input := awssso.ListAccountsInput{
		AccessToken: aws.String(as.Token.AccessToken),
		MaxResults:  aws.Int32(SSO_MAX_RESULTS),
	}
	output, err := as.ListAccounts(&input)
	if err != nil {
		return as.Accounts, err
	}

	for i, r := range output.AccountList {
		as.Accounts = append(as.Accounts, ssoconfig.AccountInfo{
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
			as.Accounts = append(as.Accounts, ssoconfig.AccountInfo{
				Id:           x + i,
				AccountId:    aws.ToString(r.AccountId),
				AccountName:  aws.ToString(r.AccountName),
				EmailAddress: aws.ToString(r.EmailAddress),
			})
		}
	}

	return as.Accounts, nil
}

// GetRoleCredentials recursively does any sts:AssumeRole calls as necessary for role-chaining
// through `Via` and returns the final set of RoleCredentials for the requested role
func (as *AWSSSO) GetRoleCredentials(accountId int64, role string) (storage.RoleCredentials, error) {
	return as.getRoleCredentials(accountId, role, map[string]bool{})
}

// getRoleCredentials is the recursive implementation of GetRoleCredentials. chainMap tracks visited
// role ARNs in the current call chain to detect loops.
func (as *AWSSSO) getRoleCredentials(accountId int64, role string, chainMap map[string]bool) (storage.RoleCredentials, error) {
	aId, err := awsparse.AccountIdToString(accountId)
	if err != nil {
		return storage.RoleCredentials{}, err
	}

	// is the role defined in the config file?
	configRole, err := as.SSOConfig.GetRole(accountId, role)
	if err != nil {
		log.Debug("SSOConfig.GetRole()", "error", err.Error(), "config", as.SSOConfig)
	}

	if configRole.Via == "" {
		// no role chaining needed — fetch directly via SSO GetRoleCredentials
		as.tokenLock.RLock()
		input := awssso.GetRoleCredentialsInput{
			AccessToken: aws.String(as.Token.AccessToken),
			AccountId:   aws.String(aId),
			RoleName:    aws.String(role),
		}
		as.tokenLock.RUnlock()

		output, err := as.sso.GetRoleCredentials(context.TODO(), &input)
		if err != nil {
			return storage.RoleCredentials{}, err
		}
		log.Debug("sso.GetRoleCredentials", "output", spew.Sdump(output))

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
	chainMap[configRole.ARN] = true
	for k := range chainMap {
		if k == configRole.Via {
			panic(fmt.Sprintf("Detected role chain loop!  Getting %s via %s", configRole.ARN, configRole.Via))
		}
		chainMap[k] = true
	}

	// Need to recursively call sts:AssumeRole in order to retrieve the STS creds for
	// the requested role
	// role has a Via
	log.Debug("Calling AssumeRole", "role", fmt.Sprintf("%s:%s", aId, role), "via", configRole.Via)
	viaAccountId, viaRole, err := awsparse.ParseRoleARN(configRole.Via)
	if err != nil {
		return storage.RoleCredentials{}, fmt.Errorf("invalid Via %s: %s", configRole.Via, err.Error())
	}

	// recurse
	creds, err := as.getRoleCredentials(viaAccountId, viaRole, chainMap)
	if err != nil {
		return storage.RoleCredentials{}, err
	}

	cfgCreds := credentials.NewStaticCredentialsProvider(
		creds.AccessKeyId,
		creds.SecretAccessKey,
		creds.SessionToken,
	)

	cfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(as.SsoRegion),
		awsconfig.WithCredentialsProvider(cfgCreds),
	)
	if err != nil {
		return storage.RoleCredentials{}, err
	}
	stsSession := sts.NewFromConfig(cfg, func(o *sts.Options) {
		if as.stsEndpoint != "" {
			o.BaseEndpoint = aws.String(as.stsEndpoint)
		}
	})

	previousAccount, _ := awsparse.AccountIdToString(creds.AccountId)
	previousRole := fmt.Sprintf("%s@%s", creds.RoleName, previousAccount)

	input := sts.AssumeRoleInput{
		// DurationSeconds: aws.Int32(900),
		RoleArn:         aws.String(awsparse.MakeRoleARN(accountId, role)),
		RoleSessionName: aws.String(previousRole),
	}
	if configRole.ExternalId != "" {
		// Optional value: https://docs.aws.amazon.com/sdk-for-go/api/service/sts/#AssumeRoleInput
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
		RoleChaining:    true, // we used AssumeRole to get these creds
	}
	return ret, nil
}
