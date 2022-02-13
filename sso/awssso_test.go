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
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/storage"
)

// mock sso
type mockSsoApi struct {
	Results []mockSsoApiResults
}

type mockSsoApiResults struct {
	ListAccountRoles   *sso.ListAccountRolesOutput
	ListAccounts       *sso.ListAccountsOutput
	GetRoleCredentials *sso.GetRoleCredentialsOutput
	Error              error
}

func (m *mockSsoApi) ListAccountRoles(ctx context.Context, params *sso.ListAccountRolesInput, optFns ...func(*sso.Options)) (*sso.ListAccountRolesOutput, error) {
	var x mockSsoApiResults
	if len(m.Results) == 0 {
		return &sso.ListAccountRolesOutput{}, fmt.Errorf("calling mocked ListAccountRoles too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.ListAccountRoles, x.Error
}

func (m *mockSsoApi) ListAccounts(ctx context.Context, params *sso.ListAccountsInput, optFns ...func(*sso.Options)) (*sso.ListAccountsOutput, error) {
	var x mockSsoApiResults
	if len(m.Results) == 0 {
		return &sso.ListAccountsOutput{}, fmt.Errorf("calling mocked ListAccounts too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.ListAccounts, x.Error
}

func (m *mockSsoApi) GetRoleCredentials(ctx context.Context, params *sso.GetRoleCredentialsInput, optFns ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error) {
	var x mockSsoApiResults
	if len(m.Results) == 0 {
		return &sso.GetRoleCredentialsOutput{}, fmt.Errorf("calling mocked GetRoleCredentials too many times")
	}
	x, m.Results = m.Results[0], m.Results[1:]
	return x.GetRoleCredentials, x.Error
}

func TestGetRoles(t *testing.T) {
	tfile, err := ioutil.TempFile("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	defer os.Remove(tfile.Name())

	duration, _ := time.ParseDuration("10s")
	as := &AWSSSO{
		SsoRegion: "us-west-1",
		StartUrl:  "https://testing.awsapps.com/start",
		ssooidc:   &mockSsoOidcApi{},
		store:     jstore,
		Roles:     map[string][]RoleInfo{},
		SSOConfig: &SSOConfig{
			Accounts: map[int64]*SSOAccount{},
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

	as.sso = &mockSsoApi{
		Results: []mockSsoApiResults{
			{
				ListAccountRoles: &sso.ListAccountRolesOutput{
					NextToken: aws.String("next-token"),
					RoleList: []types.RoleInfo{
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
					RoleList: []types.RoleInfo{
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

	for i := 0; i < 2; i++ {
		aInfo := AccountInfo{
			Id:           0,
			AccountId:    "000001111111",
			AccountName:  "MyAccount",
			EmailAddress: "foo@bar.com",
		}
		rinfo, err := as.GetRoles(aInfo)
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
	}
}

func TestGetAccounts(t *testing.T) {
	tfile, err := ioutil.TempFile("", "*storage.json")
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
		SSOConfig: &SSOConfig{},
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
	}

	as.sso = &mockSsoApi{
		Results: []mockSsoApiResults{
			{
				ListAccounts: &sso.ListAccountsOutput{
					NextToken: aws.String("next-token"),
					AccountList: []types.AccountInfo{
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
					AccountList: []types.AccountInfo{
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
}

func TestGetRoleCredentials(t *testing.T) {
	tfile, err := ioutil.TempFile("", "*storage.json")
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
		SSOConfig: &SSOConfig{},
		Token: storage.CreateTokenResponse{
			AccessToken:  "access-token",
			ExpiresIn:    42,
			ExpiresAt:    time.Now().Add(duration).Unix(),
			IdToken:      "id-token",
			RefreshToken: "refresh-token",
			TokenType:    "token-type",
		},
	}

	as.sso = &mockSsoApi{
		Results: []mockSsoApiResults{
			{
				GetRoleCredentials: &sso.GetRoleCredentialsOutput{
					RoleCredentials: &types.RoleCredentials{
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

	creds, err := as.GetRoleCredentials(int64(000001111111), "FooBar")
	assert.NoError(t, err)
	assert.Equal(t, "access-key-id", creds.AccessKeyId)
	assert.Equal(t, int64(42), creds.Expiration)
	assert.Equal(t, "secret-access-key", creds.SecretAccessKey)
	assert.Equal(t, "session-token", creds.SessionToken)

	_, err = as.GetRoleCredentials(int64(000001111111), "FooBar")
	assert.Error(t, err)
}
