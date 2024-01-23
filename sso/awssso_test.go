package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// mock sso
type mockSsoAPI struct {
	Results []mockSsoAPIResults
}

type mockSsoAPIResults struct {
	ListAccountRoles   *sso.ListAccountRolesOutput
	ListAccounts       *sso.ListAccountsOutput
	GetRoleCredentials *sso.GetRoleCredentialsOutput
	Logout             *sso.LogoutOutput
	Error              error
}

func (m *mockSsoAPI) ListAccountRoles(ctx context.Context, params *sso.ListAccountRolesInput, optFns ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error) {
	var x mockSsoAPIResults
	if len(m.Results) == 0 {
		return &sso.ListAccountRolesOutput{}, fmt.Errorf("calling mocked ListAccountRoles too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.ListAccountRoles, x.Error
}

func (m *mockSsoAPI) ListAccounts(ctx context.Context, params *sso.ListAccountsInput, optFns ...func(*sso.Options)) (*sso.ListAccountsOutput, error) {
	var x mockSsoAPIResults
	if len(m.Results) == 0 {
		return &sso.ListAccountsOutput{}, fmt.Errorf("calling mocked ListAccounts too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.ListAccounts, x.Error
}

func (m *mockSsoAPI) GetRoleCredentials(ctx context.Context, params *sso.GetRoleCredentialsInput, optFns ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error) {
	var x mockSsoAPIResults
	if len(m.Results) == 0 {
		return &sso.GetRoleCredentialsOutput{}, fmt.Errorf("calling mocked GetRoleCredentials too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.GetRoleCredentials, x.Error
}

func (m *mockSsoAPI) Logout(context.Context, *sso.LogoutInput, ...func(*sso.Options)) (*sso.LogoutOutput, error) {
	var x mockSsoAPIResults
	if len(m.Results) == 0 {
		return &sso.LogoutOutput{}, fmt.Errorf("calling mocked Logout too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.Logout, x.Error
}

func TestNewAWSSSO(t *testing.T) {
	var jstore storage.SecureStorage
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err = storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	MAX_BACKOFF_SECONDS = 0 // make unit tests go fast

	c := SSOConfig{
		StartUrl:   "https://starturl.com/start",
		SSORegion:  "us-east-1",
		settings:   &Settings{},
		MaxRetry:   1,
		MaxBackoff: 1,
	}

	s := NewAWSSSO(&c, &jstore)

	assert.NotNil(t, s)
	assert.Equal(t, jstore, s.store)
	assert.Equal(t, awsSSOClientName, s.ClientName)
	assert.Equal(t, awsSSOClientType, s.ClientType)
	assert.Equal(t, "us-east-1", s.SsoRegion)
	assert.Equal(t, c.StartUrl, s.StartUrl)
	assert.Empty(t, s.Roles)
	assert.Equal(t, &c, s.SSOConfig)
}

func TestRoleARN(t *testing.T) {
	ri := RoleInfo{
		AccountId: "1111111",
		RoleName:  "FooBar",
	}
	assert.Equal(t, "arn:aws:iam::000001111111:role/FooBar", ri.RoleArn())
}

func TestGetFieldNameRoleInfo(t *testing.T) {
	ri := RoleInfo{
		AccountId: "1111111",
		RoleName:  "FooBar",
	}

	s, err := ri.GetHeader("AccountId")
	assert.NoError(t, err)
	assert.Equal(t, "AccountId", s)

	_, err = ri.GetHeader("AccountIdDoesntExist")
	assert.Error(t, err)
}

func TestGetRoles(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		ssooidc:   &mockSsoOidcAPI{},
		store:     jstore,
		Roles:     map[string][]RoleInfo{},
		SSOConfig: &SSOConfig{
			Accounts: map[string]*SSOAccount{},
			settings: &Settings{},
		},
		urlAction: "print",
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
	}

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String("next-token"),
					RoleList: []ssotypes.RoleInfo{
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("FooBar"),
						},
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("HappyClam"),
						},
					},
				},
				Error: nil,
			},
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String(""),
					RoleList: []ssotypes.RoleInfo{
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("MooCow"),
						},
					},
				},
				Error: nil,
			},
			{
				Error: fmt.Errorf("Due to caching in AWSSSO, this error shouldn't happen"),
			},
		},
	}

	aInfo := AccountInfo{
		Id:           0,
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
	}
	rinfo, err := as.GetRoles(aInfo)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rinfo))

	// use cache
	rinfo, err = as.GetRoles(aInfo)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rinfo))

	assert.Equal(t, RoleInfo{
		Id:           0,
		Arn:          "arn:aws:iam::000001111111:role/FooBar",
		RoleName:     "FooBar",
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
		SSORegion:    "us-west-1",
		StartUrl:     "https://testing.awsapps.com/start",
	}, rinfo[0])
	assert.Equal(t, rinfo[0], as.Roles["000001111111"][0])

	assert.Equal(t, RoleInfo{
		Id:           1,
		Arn:          "arn:aws:iam::000001111111:role/HappyClam",
		RoleName:     "HappyClam",
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
		SSORegion:    "us-west-1",
		StartUrl:     "https://testing.awsapps.com/start",
	}, rinfo[1])
	assert.Equal(t, rinfo[1], as.Roles["000001111111"][1])

	assert.Equal(t, RoleInfo{
		Id:           2,
		Arn:          "arn:aws:iam::000001111111:role/MooCow",
		RoleName:     "MooCow",
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
		SSORegion:    "us-west-1",
		StartUrl:     "https://testing.awsapps.com/start",
	}, rinfo[2])
	assert.Equal(t, rinfo[2], as.Roles["000001111111"][2])

	// account doesn't exist
	aInfo = AccountInfo{
		Id:           0,
		AccountId:    "00000888888",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
	}

	_, err = as.GetRoles(aInfo)
	assert.Error(t, err)

	// Check our retry logic
	as.Roles = map[string][]RoleInfo{}
	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String(""),
					RoleList:  []ssotypes.RoleInfo{},
				},
				Error: &ssotypes.TooManyRequestsException{
					Message: aws.String("testing"),
				},
			},
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String(""),
					RoleList:  []ssotypes.RoleInfo{},
				},
				Error: &ssotypes.TooManyRequestsException{
					Message: aws.String("testing"),
				},
			},
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String(""),
					RoleList:  []ssotypes.RoleInfo{},
				},
				Error: &ssotypes.TooManyRequestsException{
					Message: aws.String("testing"),
				},
			},
		},
	}

	aInfo = AccountInfo{
		Id:           0,
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
	}
	_, err = as.GetRoles(aInfo)
	assert.Error(t, err)

	// another code path
	as.ssooidc = &mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      int64(42),
					ClientSecretExpiresAt: int64(4200),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               42,
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    42,
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	}

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Error: fmt.Errorf("Force a new token"),
			},
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String("next-token"),
					RoleList: []ssotypes.RoleInfo{
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("FooBar"),
						},
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("HappyClam"),
						},
					},
				},
				Error: nil,
			},
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String(""),
					RoleList: []ssotypes.RoleInfo{
						{
							AccountId: aws.String("000001111111"),
							RoleName:  aws.String("MooCow"),
						},
					},
				},
				Error: nil,
			},
			{
				Error: fmt.Errorf("Due to caching, this error shouldn't happen"),
			},
		},
	}

	aInfo = AccountInfo{
		Id:           0,
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
	}
	rinfo, err = as.GetRoles(aInfo)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(rinfo))

	// yet another code path
	as.Roles = map[string][]RoleInfo{} // flush cache
	as.SSOConfig = &SSOConfig{
		Accounts: map[string]*SSOAccount{},
		settings: &Settings{},
	}
	as.ssooidc = &mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      int64(42),
					ClientSecretExpiresAt: int64(4200),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               42,
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    42,
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	}

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Error: fmt.Errorf("Force a new token"),
			},
			{
				Error: fmt.Errorf("failure after re-auth"),
			},
		},
	}

	aInfo = AccountInfo{
		Id:           0,
		AccountId:    "000001111111",
		AccountName:  "MyAccount",
		EmailAddress: "foo@bar.com",
	}
	_, err = as.GetRoles(aInfo)
	assert.Error(t, err)
}

func TestGetAccounts(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		Roles:     map[string][]RoleInfo{},
		SSOConfig: &SSOConfig{
			settings: &Settings{},
		},
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
		urlAction: "print",
	}

	// this won't work
	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				ListAccounts: &sso.ListAccountsOutput{
					NextToken:   aws.String(""),
					AccountList: []ssotypes.AccountInfo{},
				},
				Error: &ssotypes.TooManyRequestsException{
					Message: aws.String("testing"),
				},
			},
			{
				ListAccounts: &sso.ListAccountsOutput{
					NextToken:   aws.String(""),
					AccountList: []ssotypes.AccountInfo{},
				},
				Error: &ssotypes.TooManyRequestsException{
					Message: aws.String("testing"),
				},
			},
		},
	}

	_, err = as.GetAccounts()
	assert.Error(t, err)

	// this time should work
	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				ListAccounts: &sso.ListAccountsOutput{
					NextToken: aws.String("next-token"),
					AccountList: []ssotypes.AccountInfo{
						{
							AccountId:    aws.String("000001111111"),
							AccountName:  aws.String("MyAccount"),
							EmailAddress: aws.String("foo@bar.com"),
						},
						{
							AccountId:    aws.String("000002222222"),
							AccountName:  aws.String("MyOtherAccount"),
							EmailAddress: aws.String("foo+other@bar.com"),
						},
					},
				},
				Error: nil,
			},
			{
				ListAccounts: &sso.ListAccountsOutput{
					NextToken: aws.String(""),
					AccountList: []ssotypes.AccountInfo{
						{
							AccountId:    aws.String("00000333333"),
							AccountName:  aws.String("MyLastAccount"),
							EmailAddress: aws.String("foo+last@bar.com"),
						},
					},
				},
				Error: nil,
			},
			{
				Error: fmt.Errorf("Due to caching, this error shouldn't happen"),
			},
		},
	}

	// first time queries the API, the second time should hit the cache
	for i := 0; i < 2; i++ {
		aInfo, err := as.GetAccounts()
		assert.NoError(t, err)
		assert.Equal(t, 3, len(aInfo))
		assert.Equal(t, AccountInfo{
			Id:           0,
			AccountId:    "000001111111",
			AccountName:  "MyAccount",
			EmailAddress: "foo@bar.com",
		}, aInfo[0])
		assert.Equal(t, aInfo[0], as.Accounts[0])

		assert.Equal(t, AccountInfo{
			Id:           1,
			AccountId:    "000002222222",
			AccountName:  "MyOtherAccount",
			EmailAddress: "foo+other@bar.com",
		}, aInfo[1])
		assert.Equal(t, aInfo[1], as.Accounts[1])

		assert.Equal(t, AccountInfo{
			Id:           2,
			AccountId:    "00000333333",
			AccountName:  "MyLastAccount",
			EmailAddress: "foo+last@bar.com",
		}, aInfo[2])
		assert.Equal(t, aInfo[2], as.Accounts[2])
	}

	// verify we handle more complex error situations
	as.Accounts = []AccountInfo{} // flush cash

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				Error: fmt.Errorf("This error is handled internally"),
			},
			{
				Error: fmt.Errorf("This error is returned"),
			},
		},
	}

	as.ssooidc = &mockSsoOidcAPI{
		Results: []mockSsoOidcAPIResults{
			{
				RegisterClient: &ssooidc.RegisterClientOutput{
					AuthorizationEndpoint: nil,
					ClientId:              aws.String("this-is-my-client-id"),
					ClientSecret:          aws.String("this-is-my-client-secret"),
					ClientIdIssuedAt:      int64(42),
					ClientSecretExpiresAt: int64(4200),
					TokenEndpoint:         nil,
				},
				Error: nil,
			},
			{
				StartDeviceAuthorization: &ssooidc.StartDeviceAuthorizationOutput{
					DeviceCode:              aws.String("device-code"),
					UserCode:                aws.String("user-code"),
					VerificationUri:         aws.String("verification-uri"),
					VerificationUriComplete: aws.String("verification-uri-complete"),
					ExpiresIn:               42,
					Interval:                5,
				},
				Error: nil,
			},
			{
				CreateToken: &ssooidc.CreateTokenOutput{
					AccessToken:  aws.String("access-token"),
					ExpiresIn:    42,
					IdToken:      aws.String("id-token"),
					RefreshToken: aws.String("refresh-token"),
					TokenType:    aws.String("token-type"),
				},
				Error: nil,
			},
		},
	}

	_, err = as.GetAccounts()
	assert.Error(t, err)
}

func TestGetRoleCredentials(t *testing.T) {
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		Roles: map[string][]RoleInfo{
			"000001111111": {
				{
					Id:           0,
					Arn:          "arn:aws:iam::000001111111:role/FooBar",
					RoleName:     "FooBar",
					AccountId:    "000001111111",
					AccountName:  "MyAccount",
					EmailAddress: "foo@bar.com",
					SSORegion:    "us-west-1",
					StartUrl:     "https://testing.awsapps.com/start",
				},
				{
					Id:           1,
					Arn:          "arn:aws:iam::000001111111:role/HappyClam",
					RoleName:     "HappyClam",
					AccountId:    "000001111111",
					AccountName:  "MyAccount",
					EmailAddress: "foo@bar.com",
					SSORegion:    "us-west-1",
					StartUrl:     "https://testing.awsapps.com/start",
				},
			},
		},
		SSOConfig: &SSOConfig{
			settings: &Settings{},
			// GetRoleCredentials() calls SSOConfig.GetRoles() so we need this too
			Accounts: map[string]*SSOAccount{
				"000001111111": {
					Roles: map[string]*SSORole{
						"FooBar": {
							ARN: "arn:aws:iam::000001111111:role/FooBar",
						},
					},
				},
			},
		},
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
	}

	as.sso = &mockSsoAPI{
		Results: []mockSsoAPIResults{
			{
				GetRoleCredentials: &sso.GetRoleCredentialsOutput{
					RoleCredentials: &ssotypes.RoleCredentials{
						AccessKeyId:     aws.String("access-key-id"),
						Expiration:      42,
						SecretAccessKey: aws.String("secret-access-key"),
						SessionToken:    aws.String("session-token"),
					},
				},
				Error: nil,
			},
			{
				Error: fmt.Errorf("invalid role"),
			},
		},
	}

	creds, err := as.GetRoleCredentials(int64(1111111), "FooBar")
	assert.NoError(t, err)
	assert.Equal(t, "access-key-id", creds.AccessKeyId)
	assert.Equal(t, int64(42), creds.Expiration)
	assert.Equal(t, "secret-access-key", creds.SecretAccessKey)
	assert.Equal(t, "session-token", creds.SessionToken)

	_, err = as.GetRoleCredentials(int64(1111111), "FooBar")
	assert.Error(t, err)
}

func TestGetFieldNameAccountInfo(t *testing.T) {
	ai := AccountInfo{
		AccountId:   "1111111",
		AccountName: "FooBar",
	}

	a, err := ai.GetHeader("AccountId")
	assert.NoError(t, err)
	assert.Equal(t, "AccountId", a)

	_, err = ai.GetHeader("AccountIdDoesntExist")
	assert.Error(t, err)
}

func TestGetAccountId64(t *testing.T) {
	ai := AccountInfo{
		AccountId: "1111111",
	}

	assert.Equal(t, int64(1111111), ai.GetAccountId64())

	ai.AccountId = "-1"
	assert.Panics(t, func() { ai.GetAccountId64() })

	ai.AccountId = "InvalidAccountId"
	assert.Panics(t, func() { ai.GetAccountId64() })

	ri := RoleInfo{
		AccountId: "1111111",
	}

	assert.Equal(t, int64(1111111), ri.GetAccountId64())

	ri.AccountId = "-1"
	assert.Panics(t, func() { ri.GetAccountId64() })

	ri.AccountId = "InvalidAccountId"
	assert.Panics(t, func() { ri.GetAccountId64() })
}
