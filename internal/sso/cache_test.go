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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	TEST_CACHE_FILE     = "./testdata/cache.json"
	TEST_ROLE_ARN       = "arn:aws:iam::707513610766:role/AWSAdministratorAccess"
	INVALID_ACCOUNT_ARN = "arn:aws:iam::707513618766:role/AWSAdministratorAccess"
	INVALID_ROLE_ARN    = "arn:aws:iam::707513610766:role/AdministratorAccess"
)

type CacheTestSuite struct {
	suite.Suite
	cache     *Cache
	cacheFile string
	settings  *Settings
}

type ProfileTests map[string]Roles

func TestCacheTestSuite(t *testing.T) {
	// copy our cache test file to a temp file
	f, err := os.CreateTemp("", "*")
	assert.NoError(t, err)
	f.Close()

	settings := &Settings{
		SSO: map[string]*SSOConfig{
			"Default": {},
		},
		HistoryLimit:   1,
		HistoryMinutes: 90,
		DefaultSSO:     "Default",
		cacheFile:      f.Name(),
		ProfileFormat:  "{{ .AccountIdPad }}:{{ .RoleName }}", // old format is easier
	}

	input, err := os.ReadFile(TEST_CACHE_FILE)
	assert.NoError(t, err)

	err = os.WriteFile(f.Name(), input, 0600) // nolint:gosec
	assert.NoError(t, err)

	c, err := OpenCache(f.Name(), settings)
	assert.NoError(t, err)

	s := &CacheTestSuite{
		cache:     c,
		cacheFile: f.Name(),
		settings:  settings,
	}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TearDownAllSuite() {
	os.Remove(suite.cacheFile)
}

func (suite *CacheTestSuite) TestNeedsRefresh() {
	t := suite.T()

	assert.True(t, suite.cache.SSO["Default"].NeedsRefresh(suite.settings.SSO["Default"], suite.settings))
}

func (suite *CacheTestSuite) TestExpired() {
	t := suite.T()
	s := SSOConfig{}

	// invalid version
	c := &Cache{
		Version: 1, // invalid
	}

	assert.Error(t, c.Expired(&s))

	c.Version = CACHE_VERSION

	s.CacheRefresh = 0
	assert.NoError(t, suite.cache.Expired(&s))

	s.CacheRefresh = 1
	assert.Error(t, suite.cache.Expired(&s))
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

func (suite *CacheTestSuite) TestPruneSSO() {
	t := suite.T()

	s := &Settings{
		SSO: map[string]*SSOConfig{
			"Primary": {},
		},
	}

	c := &Cache{
		SSO: map[string]*SSOCache{
			"Primary": {},
			"Invalid": {},
		},
	}

	c.PruneSSO(s)
	assert.Contains(t, c.SSO, "Primary")
	assert.NotContains(t, c.SSO, "Invalid")
}

func (suite *CacheTestSuite) TestGetSSOByName() {
	t := suite.T()

	c := &Cache{
		SSO: map[string]*SSOCache{
			"Primary": {
				name: "Primary",
			},
			"Secondary": {
				name: "NotSecondary",
			},
			"Invalid": {},
		},
	}

	cache := c.GetSSOByName("Primary")
	assert.NotNil(t, cache)
	assert.Equal(t, "Primary", cache.name)

	cache = c.GetSSOByName("Secondary")
	assert.NotNil(t, cache)
	assert.Equal(t, "NotSecondary", cache.name)

	cache = c.GetSSOByName("Invalid")
	assert.NotNil(t, cache)
	assert.Empty(t, cache.name)

	cache = c.GetSSOByName("Missing")
	assert.NotNil(t, cache)
	assert.Empty(t, cache.name)
}

func TestOpenCacheFailure(t *testing.T) {
	s := &Settings{}
	c, err := OpenCache("/dev/null", s)
	assert.Error(t, err)
	assert.Equal(t, int64(0), c.ConfigCreatedAt)
	assert.Equal(t, int64(1), c.Version)
}
