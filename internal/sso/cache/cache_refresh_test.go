package cache

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

	"github.com/stretchr/testify/assert"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
)

// mockRoleProvider implements ssoconfig.RoleProvider for cache tests.
type mockRoleProvider struct {
	accounts   []ssoconfig.AccountInfo
	accountErr error
	roles      map[string][]ssoconfig.RoleInfo
	roleErr    error
}

func (m *mockRoleProvider) GetAccounts() ([]ssoconfig.AccountInfo, error) {
	return m.accounts, m.accountErr
}

func (m *mockRoleProvider) GetRoles(account ssoconfig.AccountInfo) ([]ssoconfig.RoleInfo, error) {
	if m.roleErr != nil {
		return nil, m.roleErr
	}
	return m.roles[account.AccountId], nil
}

func (suite *CacheTestSuite) TestProcessSSORoles() {
	t := suite.T()

	roles := []ssoconfig.RoleInfo{
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

	config := &ssoconfig.SSOConfig{
		Accounts: map[string]*ssoconfig.SSOAccount{
			"123456789012": {
				Roles: map[string]*ssoconfig.SSORole{
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
	configBadId := &ssoconfig.SSOConfig{
		Accounts: map[string]*ssoconfig.SSOAccount{
			"not-an-id": {
				Roles: map[string]*ssoconfig.SSORole{"Foo": {}},
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
	configFull := &ssoconfig.SSOConfig{
		Accounts: map[string]*ssoconfig.SSOAccount{
			"123456789012": {
				Name:          "MyAccountName",
				DefaultRegion: "eu-west-1",
				Tags:          map[string]string{"Env": "prod"},
				Roles: map[string]*ssoconfig.SSORole{
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

func (suite *CacheTestSuite) TestAddSSORoles() {
	t := suite.T()

	mockSR := &mockSettingsReader{profileFormat: "{{ .AccountIdPad }}:{{ .RoleName }}"}

	// --- error: GetAccounts fails ---
	provErr := &mockRoleProvider{accountErr: fmt.Errorf("AWS down")}
	r := &Roles{Accounts: map[int64]*AWSAccount{}}
	err := suite.cache.addSSORoles(r, provErr, 1, mockSR)
	assert.Error(t, err)

	// --- error: no accounts returned ---
	provEmpty := &mockRoleProvider{accounts: []ssoconfig.AccountInfo{}}
	r2 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r2, provEmpty, 1, mockSR)
	assert.Error(t, err)

	// --- single account: serial path (no worker pool) ---
	prov3 := &mockRoleProvider{
		accounts: []ssoconfig.AccountInfo{
			{AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
		},
		roles: map[string][]ssoconfig.RoleInfo{
			"000001111111": {
				{RoleName: "ReadOnly", AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
			},
		},
	}
	r3 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r3, prov3, 1, mockSR)
	assert.NoError(t, err)
	assert.Len(t, r3.Accounts, 1)
	assert.Contains(t, r3.Accounts[1111111].Roles, "ReadOnly")

	// --- two accounts: exercises worker pool path ---
	prov4 := &mockRoleProvider{
		accounts: []ssoconfig.AccountInfo{
			{AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
			{AccountId: "000002222222", AccountName: "Account-000002222222", EmailAddress: "000002222222@example.com"},
		},
		roles: map[string][]ssoconfig.RoleInfo{
			"000001111111": {
				{RoleName: "Alpha", AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
			},
			"000002222222": {
				{RoleName: "Beta", AccountId: "000002222222", AccountName: "Account-000002222222", EmailAddress: "000002222222@example.com"},
			},
		},
	}
	r4 := &Roles{Accounts: map[int64]*AWSAccount{}}
	err = suite.cache.addSSORoles(r4, prov4, 1, mockSR)
	assert.NoError(t, err)
	assert.Len(t, r4.Accounts, 2)
	assert.Contains(t, r4.Accounts[1111111].Roles, "Alpha")
	assert.Contains(t, r4.Accounts[2222222].Roles, "Beta")
}

func (suite *CacheTestSuite) TestNewRoles() {
	t := suite.T()

	config := &ssoconfig.SSOConfig{
		SSORegion:     "us-east-1",
		StartUrl:      "https://testing.awsapps.com/start",
		DefaultRegion: "us-east-1",
		Accounts:      map[string]*ssoconfig.SSOAccount{},
	}
	mockSR := &mockSettingsReader{
		profileFormat: "{{ .AccountIdPad }}:{{ .RoleName }}",
	}

	// --- addSSORoles error propagated ---
	provErr := &mockRoleProvider{accountErr: fmt.Errorf("AWS down")}
	_, err := suite.cache.NewRoles(provErr, config, 1, mockSR)
	assert.Error(t, err)

	// --- happy path: single account, single role ---
	prov := &mockRoleProvider{
		accounts: []ssoconfig.AccountInfo{
			{AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
		},
		roles: map[string][]ssoconfig.RoleInfo{
			"000001111111": {
				{RoleName: "ReadOnly", AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
			},
		},
	}
	roles, err := suite.cache.NewRoles(prov, config, 1, mockSR)
	assert.NoError(t, err)
	assert.NotNil(t, roles)
	assert.Len(t, roles.Accounts, 1)
	assert.Contains(t, roles.Accounts[1111111].Roles, "ReadOnly")
	assert.Equal(t, "us-east-1", roles.SSORegion)
	assert.Equal(t, "https://testing.awsapps.com/start", roles.StartUrl)
}

func (suite *CacheTestSuite) TestCacheRefreshMocked() {
	t := suite.T()

	// config.CreatedAt() requires a real file; use our test cache file as stand-in
	ssoConf := &ssoconfig.SSOConfig{
		SSORegion:     "us-east-1",
		StartUrl:      "https://testing.awsapps.com/start",
		DefaultRegion: "us-east-1",
		Accounts:      map[string]*ssoconfig.SSOAccount{},
	}
	ssoConf.SetConfigFile(suite.cacheFile)

	settings := &mockSettingsReader{
		defaultSSO:     "Default",
		historyLimit:   1,
		historyMinutes: 90,
		cacheFile:      suite.cacheFile,
		profileFormat:  "{{ .AccountIdPad }}:{{ .RoleName }}",
		ssoNames:       []string{"Default"},
	}

	// snapshot state that we'll mutate, restore at end
	origRoles := suite.cache.SSO["Default"].Roles
	origRefreshed := suite.cache.refreshed
	defer func() {
		suite.cache.SSO["Default"].Roles = origRoles
		suite.cache.refreshed = origRefreshed
	}()

	// --- early-return: already refreshed ---
	suite.cache.refreshed = true
	added, deleted, err := suite.cache.Refresh(nil, ssoConf, "Default", 1, settings)
	assert.NoError(t, err)
	assert.Nil(t, added)
	assert.Nil(t, deleted)
	suite.cache.refreshed = false // reset for next sub-tests

	// --- NewRoles error propagated ---
	provErr := &mockRoleProvider{accountErr: fmt.Errorf("AWS down")}
	suite.cache.refreshed = false
	_, _, err = suite.cache.Refresh(provErr, ssoConf, "Default", 1, settings)
	assert.Error(t, err)

	// --- happy path: adds one role, no deletes ---
	suite.cache.SSO["Default"].Roles = &Roles{Accounts: map[int64]*AWSAccount{}}
	suite.cache.refreshed = false

	prov := &mockRoleProvider{
		accounts: []ssoconfig.AccountInfo{
			{AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
		},
		roles: map[string][]ssoconfig.RoleInfo{
			"000001111111": {
				{RoleName: "ReadOnly", AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
			},
		},
	}

	added, deleted, err = suite.cache.Refresh(prov, ssoConf, "Default", 1, settings)
	assert.NoError(t, err)
	assert.Contains(t, added, "arn:aws:iam::000001111111:role/ReadOnly")
	assert.Empty(t, deleted)
	assert.Contains(t, suite.cache.SSO["Default"].Roles.Accounts[1111111].Roles, "ReadOnly")

	// --- deleted role: pre-seed a role that AWS no longer returns ---
	suite.cache.SSO["Default"].Roles = &Roles{
		Accounts: map[int64]*AWSAccount{
			1111111: {
				Roles: map[string]*AWSRole{
					"OldRole": {Arn: "arn:aws:iam::000001111111:role/OldRole"},
				},
				Tags: map[string]string{},
			},
		},
	}
	suite.cache.refreshed = false

	provEmpty := &mockRoleProvider{
		accounts: []ssoconfig.AccountInfo{
			{AccountId: "000001111111", AccountName: "Account-000001111111", EmailAddress: "000001111111@example.com"},
		},
		roles: map[string][]ssoconfig.RoleInfo{
			"000001111111": {}, // no roles returned
		},
	}

	added, deleted, err = suite.cache.Refresh(provEmpty, ssoConf, "Default", 1, settings)
	assert.NoError(t, err)
	assert.Empty(t, added)
	assert.Contains(t, deleted, "arn:aws:iam::000001111111:role/OldRole")
}
