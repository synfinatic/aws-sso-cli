package sso

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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func (suite *CacheTestSuite) TestProcessSSORoles() {
	t := suite.T()

	roles := []RoleInfo{
		{
			Id:           0,
			Arn:          "arn:aws:iam::123456789012:role/testing",
			RoleName:     "testing",
			AccountId:    "123456789012",
			AccountName:  "MyTestAccount",
			EmailAddress: "testing@domain.com",
			Expires:      555555555,
			Profile:      "TestingAccountTesting",
			Region:       "us-east-1",
			SSORegion:    "us-east-2",
			StartUrl:     "https://fake.awsapps.com/start",
		},
	}

	r := Roles{
		Accounts: map[int64]*AWSAccount{},
	}
	cache := SSOCache{
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{
				123456789012: {},
			},
		},
	}

	processSSORoles(roles, &cache, &r)
	assert.Len(t, r.Accounts, 1)
	assert.Len(t, r.Accounts[123456789012].Roles, 1)
	assert.Equal(t, "MyTestAccount", r.Accounts[123456789012].Alias)
	assert.Equal(t, "testing@domain.com", r.Accounts[123456789012].EmailAddress)
	assert.Equal(t, "arn:aws:iam::123456789012:role/testing", r.Accounts[123456789012].Roles["testing"].Arn)
	assert.Len(t, r.Accounts[123456789012].Tags, 0)

	assert.Equal(t, "MyTestAccount", r.Accounts[123456789012].Roles["testing"].Tags["AccountAlias"])
	assert.Equal(t, "123456789012", r.Accounts[123456789012].Roles["testing"].Tags["AccountID"])
	assert.Equal(t, "testing@domain.com", r.Accounts[123456789012].Roles["testing"].Tags["Email"])
	assert.Equal(t, "testing", r.Accounts[123456789012].Roles["testing"].Tags["Role"])
}

func (suite *CacheTestSuite) TestAddConfigRoles() {
	t := suite.T()

	config := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": {
				Roles: map[string]*SSORole{
					"Foo": {},
					"Bar": {},
				},
			},
		},
	}

	roles := &Roles{
		Accounts: map[int64]*AWSAccount{},
	}

	err := suite.cache.addConfigRoles(roles, config)
	assert.NoError(t, err)

	// invalid accountId returns error
	configBadId := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"not-an-id": {
				Roles: map[string]*SSORole{"Foo": {}},
			},
		},
	}
	err = suite.cache.addConfigRoles(roles, configBadId)
	assert.Error(t, err)

	// account present in SSO: tags, name, default region and role decorations applied
	roles2 := &Roles{
		Accounts: map[int64]*AWSAccount{
			123456789012: {
				Alias:        "MyAlias",
				EmailAddress: "alias@example.com",
				Tags:         map[string]string{},
				Roles: map[string]*AWSRole{
					"Foo": {
						Arn:  "arn:aws:iam::123456789012:role/Foo",
						Tags: map[string]string{},
					},
					"Bar": {
						Arn:  "arn:aws:iam::123456789012:role/Bar",
						Tags: map[string]string{},
					},
				},
			},
		},
	}
	configFull := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": {
				Name:          "MyAccountName",
				DefaultRegion: "eu-west-1",
				Tags:          map[string]string{"Env": "prod"},
				Roles: map[string]*SSORole{
					"Foo": {
						DefaultRegion: "us-west-2",
						Via:           "arn:aws:iam::123456789012:role/Bar",
						Tags:          map[string]string{"Team": "infra"},
					},
					"Bar": {},
					// role not in SSO – exercises the "don't have access" debug log path
					"NotInSSO": {},
				},
			},
		},
	}
	err = suite.cache.addConfigRoles(roles2, configFull)
	assert.NoError(t, err)

	// account-level name and default region
	assert.Equal(t, "MyAccountName", roles2.Accounts[123456789012].Name)
	assert.Equal(t, "eu-west-1", roles2.Accounts[123456789012].DefaultRegion)

	// account-level tag propagated to account
	assert.Equal(t, "prod", roles2.Accounts[123456789012].Tags["Env"])

	// Foo: role-level DefaultRegion overrides account default (struct field)
	assert.Equal(t, "us-west-2", roles2.Accounts[123456789012].Roles["Foo"].DefaultRegion)
	// Tag is only set from the pre-existing DefaultRegion in the SSO-tags pass;
	// since the role started with no DefaultRegion the tag is not present.
	assert.Empty(t, roles2.Accounts[123456789012].Roles["Foo"].Tags["DefaultRegion"])

	// Foo: Via is set
	assert.Equal(t, "arn:aws:iam::123456789012:role/Bar", roles2.Accounts[123456789012].Roles["Foo"].Via)

	// Foo: role-level tag applied
	assert.Equal(t, "infra", roles2.Accounts[123456789012].Roles["Foo"].Tags["Team"])

	// Foo: account-level tag propagated to role
	assert.Equal(t, "prod", roles2.Accounts[123456789012].Roles["Foo"].Tags["Env"])

	// AccountName tag set when Name is non-empty
	assert.Equal(t, "MyAccountName", roles2.Accounts[123456789012].Roles["Foo"].Tags["AccountName"])
}

// makeTestAWSSSOWithMock builds an AWSSSO suitable for unit tests using a mockSsoAPI.
func makeTestAWSSSOWithMock(t *testing.T, results []mockSsoAPIResults) (*AWSSSO, func()) {
	t.Helper()
	tfile, err := os.CreateTemp("", "*storage.json")
	assert.NoError(t, err)

	jstore, err := storage.OpenJsonStore(tfile.Name())
	assert.NoError(t, err)

	duration := 10 * time.Second
	as := &AWSSSO{
		SsoRegion: "us-east-1",
		StartUrl:  "https://testing.awsapps.com/start",
		store:     jstore,
		Roles:     map[string][]RoleInfo{},
		SSOConfig: &SSOConfig{
			Accounts:  map[string]*SSOAccount{},
			SSORegion: "us-east-1",
			StartUrl:  "https://testing.awsapps.com/start",
			settings:  &Settings{},
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
	as.sso = &mockSsoAPI{Results: results}

	cleanup := func() { os.Remove(tfile.Name()) } // #nosec G703 -- temp file path from os.CreateTemp
	return as, cleanup
}

// listAccountsResult is a helper that constructs a single-page ListAccountsOutput.
func listAccountsResult(ids ...string) mockSsoAPIResults {
	accounts := make([]ssotypes.AccountInfo, len(ids))
	for i, id := range ids {
		accounts[i] = ssotypes.AccountInfo{
			AccountId:    aws.String(id),
			AccountName:  aws.String("Account-" + id),
			EmailAddress: aws.String(id + "@example.com"),
		}
	}
	return mockSsoAPIResults{
		ListAccounts: &sso.ListAccountsOutput{
			NextToken:   aws.String(""),
			AccountList: accounts,
		},
	}
}

// listRolesResult is a helper that constructs a single-page ListAccountRolesOutput.
func listRolesResult(accountId string, roles ...string) mockSsoAPIResults {
	ri := make([]ssotypes.RoleInfo, len(roles))
	for i, r := range roles {
		ri[i] = ssotypes.RoleInfo{
			AccountId: aws.String(accountId),
			RoleName:  aws.String(r),
		}
	}
	return mockSsoAPIResults{
		ListAccountRoles: &sso.ListAccountRolesOutput{
			NextToken: aws.String(""),
			RoleList:  ri,
		},
	}
}

func (suite *CacheTestSuite) TestAddSSORoles() {
	t := suite.T()

	origBackoff := MAX_BACKOFF_SECONDS
	origRetry := MAX_RETRY_ATTEMPTS
	MAX_BACKOFF_SECONDS = 0 // keep retries fast
	MAX_RETRY_ATTEMPTS = 0  // no retries so mock isn't over-called
	defer func() {
		MAX_BACKOFF_SECONDS = origBackoff
		MAX_RETRY_ATTEMPTS = origRetry
	}()

	// --- error: GetAccounts fails ---
	as, cleanup := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		{ListAccounts: &sso.ListAccountsOutput{}, Error: fmt.Errorf("AWS down")},
	})
	defer cleanup()

	r := &Roles{Accounts: map[int64]*AWSAccount{}}
	err := suite.cache.addSSORoles(r, as, 1)
	assert.Error(t, err)

	// --- error: no accounts returned ---
	as2, cleanup2 := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		{
			ListAccounts: &sso.ListAccountsOutput{
				NextToken:   aws.String(""),
				AccountList: []ssotypes.AccountInfo{},
			},
		},
	})
	defer cleanup2()

	r2 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r2, as2, 1)
	assert.Error(t, err)

	// --- single account: serial path (no worker pool) ---
	as3, cleanup3 := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		listAccountsResult("000001111111"),
		listRolesResult("000001111111", "ReadOnly"),
	})
	defer cleanup3()

	r3 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r3, as3, 1)
	assert.NoError(t, err)
	assert.Len(t, r3.Accounts, 1)
	assert.Contains(t, r3.Accounts[1111111].Roles, "ReadOnly")

	// --- two accounts: exercises worker pool path ---
	as4, cleanup4 := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		listAccountsResult("000001111111", "000002222222"),
		listRolesResult("000001111111", "Alpha"), // serial first account
		listRolesResult("000002222222", "Beta"),  // worker pool second account
	})
	defer cleanup4()

	r4 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r4, as4, 1)
	assert.NoError(t, err)
	assert.Len(t, r4.Accounts, 2)
	assert.Contains(t, r4.Accounts[1111111].Roles, "Alpha")
	assert.Contains(t, r4.Accounts[2222222].Roles, "Beta")
}

func (suite *CacheTestSuite) TestNewRoles() {
	t := suite.T()

	origBackoff := MAX_BACKOFF_SECONDS
	origRetry := MAX_RETRY_ATTEMPTS
	MAX_BACKOFF_SECONDS = 0
	MAX_RETRY_ATTEMPTS = 0
	defer func() {
		MAX_BACKOFF_SECONDS = origBackoff
		MAX_RETRY_ATTEMPTS = origRetry
	}()

	config := &SSOConfig{
		SSORegion:     "us-east-1",
		StartUrl:      "https://testing.awsapps.com/start",
		DefaultRegion: "us-east-1",
		Accounts:      map[string]*SSOAccount{},
		settings: &Settings{
			DefaultSSO:    "Default",
			ProfileFormat: "{{ .AccountIdPad }}:{{ .RoleName }}",
		},
	}
	suite.cache.settings.ProfileFormat = "{{ .AccountIdPad }}:{{ .RoleName }}"

	// --- addSSORoles error propagated ---
	as, cleanup := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		{ListAccounts: &sso.ListAccountsOutput{}, Error: fmt.Errorf("AWS down")},
	})
	defer cleanup()

	_, err := suite.cache.NewRoles(as, config, 1)
	assert.Error(t, err)

	// --- happy path: single account, single role ---
	as2, cleanup2 := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		listAccountsResult("000001111111"),
		listRolesResult("000001111111", "ReadOnly"),
	})
	defer cleanup2()

	roles, err := suite.cache.NewRoles(as2, config, 1)
	assert.NoError(t, err)
	assert.NotNil(t, roles)
	assert.Len(t, roles.Accounts, 1)
	assert.Contains(t, roles.Accounts[1111111].Roles, "ReadOnly")
	assert.Equal(t, "us-east-1", roles.SSORegion)
	assert.Equal(t, "https://testing.awsapps.com/start", roles.StartUrl)
}

func (suite *CacheTestSuite) TestCacheRefreshMocked() {
	t := suite.T()

	origBackoff := MAX_BACKOFF_SECONDS
	origRetry := MAX_RETRY_ATTEMPTS
	MAX_BACKOFF_SECONDS = 0
	MAX_RETRY_ATTEMPTS = 0
	defer func() {
		MAX_BACKOFF_SECONDS = origBackoff
		MAX_RETRY_ATTEMPTS = origRetry
	}()

	// config.CreatedAt() requires a real file; use our test cache file as stand-in
	settings := &Settings{
		SSO: map[string]*SSOConfig{
			"Default": {
				SSORegion:     "us-east-1",
				StartUrl:      "https://testing.awsapps.com/start",
				DefaultRegion: "us-east-1",
				Accounts:      map[string]*SSOAccount{},
			},
		},
		HistoryLimit:   1,
		HistoryMinutes: 90,
		DefaultSSO:     "Default",
		cacheFile:      suite.cacheFile,
		configFile:     suite.cacheFile, // needed for config.CreatedAt()
		ProfileFormat:  "{{ .AccountIdPad }}:{{ .RoleName }}",
	}
	settings.SSO["Default"].settings = settings

	// snapshot state that we'll mutate, restore at end
	origSettings := suite.cache.settings
	origRoles := suite.cache.SSO["Default"].Roles
	origRefreshed := suite.cache.refreshed
	defer func() {
		suite.cache.settings = origSettings
		suite.cache.SSO["Default"].Roles = origRoles
		suite.cache.refreshed = origRefreshed
	}()

	suite.cache.settings = settings

	// --- early-return: already refreshed ---
	suite.cache.refreshed = true
	added, deleted, err := suite.cache.Refresh(nil, settings.SSO["Default"], "Default", 1)
	assert.NoError(t, err)
	assert.Equal(t, 0, added)
	assert.Equal(t, 0, deleted)
	suite.cache.refreshed = false // reset for next sub-tests

	// --- NewRoles error propagated ---
	asErr, cleanup := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		{ListAccounts: &sso.ListAccountsOutput{}, Error: fmt.Errorf("AWS down")},
	})
	defer cleanup()

	suite.cache.refreshed = false
	_, _, err = suite.cache.Refresh(asErr, settings.SSO["Default"], "Default", 1)
	assert.Error(t, err)

	// --- happy path: adds one role, no deletes ---
	// make sure the cache has no existing roles for "Default" so we get a clean add count
	suite.cache.SSO["Default"].Roles = &Roles{Accounts: map[int64]*AWSAccount{}}
	suite.cache.refreshed = false

	as, cleanup2 := makeTestAWSSSOWithMock(t, []mockSsoAPIResults{
		listAccountsResult("000001111111"),
		listRolesResult("000001111111", "ReadOnly"),
	})
	defer cleanup2()

	added, deleted, err = suite.cache.Refresh(as, settings.SSO["Default"], "Default", 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, added)
	assert.Equal(t, 0, deleted)
	assert.Contains(t, suite.cache.SSO["Default"].Roles.Accounts[1111111].Roles, "ReadOnly")
}

/*
func (suite *CacheTestSuite) TestCacheRefresh() {
	t := suite.T()

	settings := &Settings{
		SSO: map[string]*SSOConfig{
			"Default": {
				SSORegion:     "us-east-1",
				DefaultRegion: "us-east-1",
			},
		},
		HistoryLimit:   1,
		HistoryMinutes: 90,
		DefaultSSO:     "Default",
		cacheFile:      suite.cacheFile,
		ProfileFormat:  "{{ .AccountIdPad }}:{{ .RoleName }}",
	}
	settings.SSO["Default"].settings = settings

	storeFile, err := os.CreateTemp("", "*")
	assert.NoError(t, err)
	storeFile.Close()
	defer os.Remove(storeFile.Name())

	jstore, err := storage.OpenJsonStore(storeFile.Name())
	assert.NoError(t, err)

	sso := NewAWSSSO(suite.settings.SSO["Default"], &jstore)

	// Ensure the SecureStorage interface is implemented correctly
	added, deleted, err := suite.cache.Refresh(sso, settings.SSO["Default"], "Default", 1)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), suite.cache.ConfigCreatedAt)
	assert.Equal(t, int64(1), suite.cache.Version)
	assert.Equal(t, 1, added)
	assert.Equal(t, 0, deleted)
}
*/
