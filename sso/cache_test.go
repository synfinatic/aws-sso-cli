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
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	// "github.com/davecgh/go-spew/spew"
	goyaml "github.com/goccy/go-yaml"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	TEST_CACHE_FILE      = "./testdata/cache.json"
	TEST_ROLES_TEST_FILE = "./testdata/roles_tests.yaml"
	TEST_ROLE_ARN        = "arn:aws:iam::707513610766:role/AWSAdministratorAccess"
	INVALID_ACCOUNT_ARN  = "arn:aws:iam::707513618766:role/AWSAdministratorAccess"
	INVALID_ROLE_ARN     = "arn:aws:iam::707513610766:role/AdministratorAccess"
)

type CacheTestSuite struct {
	suite.Suite
	cache     *Cache
	cacheFile string
}

type ProfileTests map[string]Roles

func TestCacheTestSuite(t *testing.T) {
	// copy our cache test file to a temp file
	f, err := os.CreateTemp("", "*")
	assert.NoError(t, err)
	f.Close()

	settings := &Settings{
		HistoryLimit:   1,
		HistoryMinutes: 90,
		DefaultSSO:     "Default",
		cacheFile:      f.Name(),
	}

	input, err := ioutil.ReadFile(TEST_CACHE_FILE)
	assert.NoError(t, err)

	err = ioutil.WriteFile(f.Name(), input, 0600)
	assert.NoError(t, err)

	c, err := OpenCache(f.Name(), settings)
	assert.NoError(t, err)

	s := &CacheTestSuite{
		cache:     c,
		cacheFile: f.Name(),
	}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TearDownAllSuite() {
	os.Remove(suite.cacheFile)
}

func (suite *CacheTestSuite) TestAddHistory() {
	t := suite.T()

	c := &Cache{
		settings: &Settings{
			HistoryLimit:   1,
			HistoryMinutes: 90,
		},
		ssoName: "Default",
		SSO:     map[string]*SSOCache{},
	}
	c.SSO["Default"] = &SSOCache{
		LastUpdate: 2345,
		History:    []string{},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{
				123456789012: {
					Alias: "MyAccount",
					Roles: map[string]*AWSRole{
						"Foo": {
							Arn:  "aws:arn:iam::123456789012:role/Foo",
							Tags: map[string]string{},
						},
						"Bar": {
							Arn:  "aws:arn:iam::123456789012:role/Bar",
							Tags: map[string]string{},
						},
					},
				},
			},
		},
	}

	cache := c.GetSSO()
	assert.Equal(t, []string{}, cache.History)

	c.AddHistory("aws:arn:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"aws:arn:iam::123456789012:role/Foo"}, cache.History)
	c.AddHistory("aws:arn:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"aws:arn:iam::123456789012:role/Foo"}, cache.History)

	c.AddHistory("aws:iam:arn::1234567889012:role/Bar")
	assert.Equal(t, []string{"aws:iam:arn::1234567889012:role/Bar"}, cache.History)
	c.AddHistory("aws:iam:arn::1234567889012:role/Bar")
	assert.Equal(t, []string{"aws:iam:arn::1234567889012:role/Bar"}, cache.History)

	c.settings.HistoryLimit = 2
	c.AddHistory("aws:arn:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"aws:arn:iam::123456789012:role/Foo",
		"aws:iam:arn::1234567889012:role/Bar"}, cache.History)

	// this should be a no-op
	c.AddHistory("aws:arn:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"aws:arn:iam::123456789012:role/Foo",
		"aws:iam:arn::1234567889012:role/Bar"}, cache.History)

	// reorder args
	c.AddHistory("arn:aws:iam::123456789012:role/Baz")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Baz",
		"aws:arn:iam::123456789012:role/Foo"}, cache.History)

	c.AddHistory("aws:arn:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"aws:arn:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Baz"}, cache.History)

	assert.Contains(t, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags, "History")
}

func (suite *CacheTestSuite) setupDeleteOldHistory() *Cache {
	c := &Cache{
		settings: &Settings{
			HistoryLimit:   2,
			HistoryMinutes: 5,
		},
		ssoName: "Default",
		SSO:     map[string]*SSOCache{},
	}
	now := time.Now().Unix()
	c.SSO["Default"] = &SSOCache{
		LastUpdate: now - 5,
		History: []string{
			"arn:aws:iam::123456789012:role/Test",
			"arn:aws:iam::123456789012:role/Foo",
		},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{
				123456789012: {
					Roles: map[string]*AWSRole{
						"Test": {
							Tags: map[string]string{
								"History": fmt.Sprintf("MyAlias:Test,%d", now-5),
							},
						},
						"Foo": {
							Tags: map[string]string{
								"History": fmt.Sprintf("MyOtherAlias:Foo,%d", now-85),
							},
						},
					},
				},
			},
		},
	}
	return c
}

func (suite *CacheTestSuite) TestDeleteOldHistory() {
	t := suite.T()

	c := suite.setupDeleteOldHistory()

	// check setup
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// no-op because we haven't timed out yet
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	c = suite.setupDeleteOldHistory()

	// no-op when HistoryMinutes <= 0
	c.settings.HistoryLimit = 1
	c.settings.HistoryMinutes = 0
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// remove one due to HistoryLimit
	c.settings.HistoryMinutes = 1
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
	}, c.GetSSO().History)
	assert.NotContains(t, "History",
		c.SSO["Default"].Roles.Accounts[123456789012].Roles["Foo"].Tags)

	// setup logger for tests
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	oldLogger := GetLogger()
	SetLogger(logger)
	defer SetLogger(oldLogger)

	// remove one because of HistoryMinutes expires
	c = suite.setupDeleteOldHistory()
	c.settings.HistoryMinutes = 1
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "Removed expired history role")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Test"}, c.GetSSO().History)

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam:")
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "Unable to parse History ARN")
	hook.Reset()

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "but no role by that name")
	hook.Reset()

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::1234567890:role/NoHistoryTag")
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "but no account by that name")
	hook.Reset()

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["NoHistoryTag"] = &AWSRole{}
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "is in history list without a History tag")
	hook.Reset()

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo",
		},
	}
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "Too few fields for")

	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo,kkkk",
		},
	}
	c.deleteOldHistory()
	assert.NotNil(t, hook.LastEntry())
	assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	assert.Contains(t, hook.LastEntry().Message, "Unable to parse")
}

func (suite *CacheTestSuite) TestExpired() {
	t := suite.T()
	assert.Error(t, suite.cache.Expired(nil))
}

func (suite *CacheTestSuite) TestGetRole() {
	t := suite.T()
	r, _ := suite.cache.GetRole(TEST_ROLE_ARN)
	assert.Equal(t, int64(707513610766), r.AccountId)
	assert.Equal(t, "AWSAdministratorAccess", r.RoleName)
	assert.Equal(t, TEST_ROLE_ARN, r.Arn)
	assert.Equal(t, "Dev Account", r.AccountName)
	assert.Equal(t, "control-tower-dev-sub1-aws", r.AccountAlias)
	assert.Equal(t, "test+control-tower-sub1@ourcompany.com", r.EmailAddress)
	assert.Equal(t, "", r.Profile)
	assert.Equal(t, "", r.DefaultRegion)
	assert.Equal(t, "us-east-1", r.SSORegion)
	assert.Equal(t, "https://d-754545454.awsapps.com/start", r.StartUrl)
	assert.Equal(t, "Default", r.SSO)

	tags := map[string]string{
		"AccountAlias": "control-tower-dev-sub1-aws",
		"AccountID":    "707513610766",
		"AccountName":  "Dev Account",
		"Email":        "test+control-tower-sub1@ourcompany.com",
		"Role":         "AWSAdministratorAccess",
		"Type":         "Sub Account",
	}

	assert.Equal(t, tags, r.Tags)
}

func (suite *CacheTestSuite) TestAccountIds() {
	t := suite.T()

	ids := suite.cache.GetSSO().Roles.AccountIds()
	assert.Equal(t, 4, len(ids))
}

func (suite *CacheTestSuite) TestGetAllRoles() {
	t := suite.T()

	cache := suite.cache.GetSSO()
	roles := cache.Roles.GetAllRoles()
	assert.Equal(t, 19, len(roles))

	aroles := cache.Roles.GetAccountRoles(707513610766)
	assert.Equal(t, 4, len(aroles))
	aroles = cache.Roles.GetAccountRoles(502470824893)
	assert.Equal(t, 4, len(aroles))
	aroles = cache.Roles.GetAccountRoles(258234615182)
	assert.Equal(t, 7, len(aroles))
}

func (suite *CacheTestSuite) TestGetAllTags() {
	t := suite.T()
	cache := suite.cache.GetSSO()

	tl := cache.Roles.GetAllTags()
	assert.Equal(t, 9, len(*tl))
	tl = suite.cache.GetAllTagsSelect()
	assert.Equal(t, 9, len(*tl))
}

func (suite *CacheTestSuite) TestGetRoleTags() {
	t := suite.T()
	cache := suite.cache.GetSSO()

	rt := cache.Roles.GetRoleTags()
	assert.Equal(t, 19, len(*rt))
	rt = suite.cache.GetRoleTagsSelect()
	assert.Equal(t, 19, len(*rt))
}

func (suite *CacheTestSuite) TestMatchingRoles() {
	t := suite.T()
	cache := suite.cache.GetSSO()

	match := map[string]string{
		"Type": "Main Account",
		"Foo":  "Bar",
	}
	roles := cache.Roles.MatchingRoles(match)
	assert.Equal(t, 1, len(roles))

	match["Nothing"] = "Matches"
	roles = cache.Roles.MatchingRoles(match)
	assert.Equal(t, 0, len(roles))
}

func (suite *CacheTestSuite) TestIsExpired() {
	t := suite.T()

	r, _ := suite.cache.GetRole(TEST_ROLE_ARN)
	assert.True(t, r.IsExpired())
}

func (suite *CacheTestSuite) BadRole() {
	t := suite.T()
	_, err := suite.cache.GetRole(INVALID_ROLE_ARN)
	assert.Error(t, err)

	_, err = suite.cache.GetRole(INVALID_ACCOUNT_ARN)
	assert.Error(t, err)
}

func (suite *CacheTestSuite) TestVersion() {
	t := suite.T()
	assert.Equal(t, int64(CACHE_VERSION), suite.cache.Version)

	err := suite.cache.Save(false)
	assert.NoError(t, err)
	assert.Equal(t, int64(CACHE_VERSION), suite.cache.Version)
}

func (suite *CacheTestSuite) TestGetSSO() {
	t := suite.T()

	suite.cache.ssoName = "Invalid"
	cache := suite.cache.GetSSO()
	assert.Empty(t, cache.Roles.Accounts)
	assert.Empty(t, cache.History)
	assert.Equal(t, int64(0), cache.LastUpdate)

	suite.cache.ssoName = "Default"
	cache = suite.cache.GetSSO()
	assert.NotEmpty(t, cache.Roles)
	assert.Empty(t, cache.History)
	assert.NotEqual(t, 0, cache.LastUpdate)
}

func (suite *CacheTestSuite) TestCacheFile() {
	t := suite.T()
	assert.Equal(t, suite.cacheFile, suite.cache.CacheFile())
}

func (suite *CacheTestSuite) TestMarkRolesExpired() {
	t := suite.T()
	err := suite.cache.MarkRolesExpired()
	assert.NoError(t, err)

	sso := suite.cache.GetSSO()
	for _, account := range sso.Roles.Accounts {
		for _, role := range account.Roles {
			assert.Equal(t, int64(0), (*role).Expires)
		}
	}
}

func (suite *CacheTestSuite) TestSetRoleExpires() {
	t := suite.T()
	err := suite.cache.SetRoleExpires(TEST_ROLE_ARN, 12344553243)
	assert.NoError(t, err)

	flat, err := suite.cache.GetRole(TEST_ROLE_ARN)
	assert.NoError(t, err)
	assert.Equal(t, int64(12344553243), flat.Expires)

	err = suite.cache.SetRoleExpires(INVALID_ROLE_ARN, 12344553243)
	assert.Error(t, err)
}

func (suite *CacheTestSuite) TestCheckProfiles() {
	t := suite.T()
	tests := ProfileTests{}

	data, err := ioutil.ReadFile(TEST_ROLES_TEST_FILE)
	assert.NoError(t, err)

	err = goyaml.Unmarshal(data, &tests)
	assert.NoError(t, err)

	for testName, testData := range tests {
		err := testData.checkProfiles(suite.cache.settings)
		if strings.HasPrefix(testName, "Invalid") {
			assert.Error(t, err, testName)
		} else {
			assert.NoError(t, err, testName)
		}
	}

	badSettings := *suite.cache.settings
	badSettings.ProfileFormat = "{{ .AccountName }}"
	r := tests["Valid1"]
	err = r.checkProfiles(&badSettings)
	assert.NoError(t, err)

	r = tests["Valid2"]
	err = r.checkProfiles(&badSettings)
	assert.Error(t, err)

	badSettings.ProfileFormat = "{{ .RoleName }}"
	r = tests["Valid3"]
	err = r.checkProfiles(&badSettings)
	assert.Error(t, err)
}
