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
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	testlogger "github.com/synfinatic/flexlog/test"
)

const (
	TEST_CACHE_FILE     = "../testdata/cache.json"
	TEST_ROLE_ARN       = "arn:aws:iam::707513610766:role/AWSAdministratorAccess"
	INVALID_ACCOUNT_ARN = "arn:aws:iam::707513618766:role/AWSAdministratorAccess"
	INVALID_ROLE_ARN    = "arn:aws:iam::707513610766:role/AdministratorAccess"
)

// mockSettingsReader is a SettingsReader implementation for tests.
type mockSettingsReader struct {
	cacheFile      string
	defaultSSO     string
	historyLimit   int64
	historyMinutes int64
	profileFormat  string
	envVarTags     map[string]string
	threads        int
	ssoNames       []string
}

func (m *mockSettingsReader) GetCacheFile() string             { return m.cacheFile }
func (m *mockSettingsReader) GetDefaultSSO() string            { return m.defaultSSO }
func (m *mockSettingsReader) GetHistoryLimit() int64           { return m.historyLimit }
func (m *mockSettingsReader) GetHistoryMinutes() int64         { return m.historyMinutes }
func (m *mockSettingsReader) GetProfileFormat() string         { return m.profileFormat }
func (m *mockSettingsReader) GetEnvVarTags() map[string]string { return m.envVarTags }
func (m *mockSettingsReader) GetThreads() int {
	if m.threads == 0 {
		return 1
	}
	return m.threads
}
func (m *mockSettingsReader) GetSSONames() []string { return m.ssoNames }

// CacheTestSuite is the test suite for cache tests.
type CacheTestSuite struct {
	suite.Suite
	cache     *Cache
	cacheFile string
	settings  *mockSettingsReader
	ssoConfig *ssoconfig.SSOConfig
}

func TestCacheTestSuite(t *testing.T) {
	// copy our cache test file to a temp file
	f, err := os.CreateTemp("", "*")
	assert.NoError(t, err)
	f.Close()

	settings := &mockSettingsReader{
		defaultSSO:     "Default",
		historyLimit:   1,
		historyMinutes: 90,
		profileFormat:  "{{ .AccountIdPad }}:{{ .RoleName }}", // old format is easier
		ssoNames:       []string{"Default"},
	}
	settings.cacheFile = f.Name()

	input, err := os.ReadFile(TEST_CACHE_FILE)
	assert.NoError(t, err)

	err = os.WriteFile(f.Name(), input, 0600) // nolint:gosec
	assert.NoError(t, err)

	c, err := OpenCache(f.Name(), settings)
	assert.NoError(t, err)

	ssoConf := &ssoconfig.SSOConfig{}
	ssoConf.SetConfigFile(f.Name())

	s := &CacheTestSuite{
		cache:     c,
		cacheFile: f.Name(),
		settings:  settings,
		ssoConfig: ssoConf,
	}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TearDownAllSuite() {
	os.Remove(suite.cacheFile)
}

func (suite *CacheTestSuite) TestNeedsRefresh() {
	t := suite.T()
	assert.True(t, suite.cache.SSO["Default"].NeedsRefresh(suite.ssoConfig, suite.settings))
}

func (suite *CacheTestSuite) TestExpired() {
	t := suite.T()
	s := &ssoconfig.SSOConfig{}

	// invalid version
	c := &Cache{
		Version: 1, // invalid
	}

	assert.Error(t, c.Expired(s))

	c.Version = CACHE_VERSION

	s.CacheRefresh = 0
	assert.NoError(t, suite.cache.Expired(s))

	s.CacheRefresh = 1
	assert.Error(t, suite.cache.Expired(s))
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

func (suite *CacheTestSuite) TestGetSetSSOName() {
	t := suite.T()
	orig := suite.cache.ssoName
	suite.cache.SetSSOName("MySSO")
	assert.Equal(t, "MySSO", suite.cache.GetSSOName())
	suite.cache.SetSSOName(orig)
}

func (suite *CacheTestSuite) TestIsSetRefreshed() {
	t := suite.T()
	suite.cache.SetRefreshed(true)
	assert.True(t, suite.cache.IsRefreshed())
	suite.cache.SetRefreshed(false)
	assert.False(t, suite.cache.IsRefreshed())
}

func (suite *CacheTestSuite) TestPruneSSO() {
	t := suite.T()

	s := &mockSettingsReader{
		ssoNames: []string{"Primary"},
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
	s := &mockSettingsReader{}
	c, err := OpenCache("/dev/null", s)
	assert.Error(t, err)
	assert.Equal(t, int64(0), c.ConfigCreatedAt)
	assert.Equal(t, int64(1), c.Version)
}

// --- history tests ---

func (suite *CacheTestSuite) TestAddHistory() {
	t := suite.T()

	sr := &mockSettingsReader{historyLimit: 1, historyMinutes: 90}

	c := &Cache{
		ssoName: "Default",
		SSO: map[string]*SSOCache{
			"Default": {
				name:       "Default",
				LastUpdate: 2345,
				History:    []string{},
				Roles: &Roles{
					Accounts: map[int64]*AWSAccount{
						123456789012: {
							Alias: "MyAccount",
							Roles: map[string]*AWSRole{
								"Foo": {
									Arn: "arn:aws:iam::123456789012:role/Foo",
									Tags: map[string]string{
										"AccountAlias": "MyAccount",
										"RoleName":     "Foo",
									},
								},
								"Bar": {
									Arn: "arn:aws:iam::123456789012:role/Bar",
									Tags: map[string]string{
										"AccountAlias": "MyAccount",
										"RoleName":     "Bar",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cache := c.GetSSO()
	assert.Equal(t, []string{}, cache.History)

	now := time.Now().Unix()

	// Basic add
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Foo"}, cache.History)
	tag := fmt.Sprintf("MyAccount:Foo,%d", now)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags["History"])

	// Add again which should be a no-op
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Foo"}, cache.History)
	tag = fmt.Sprintf("MyAccount:Foo,%d", now)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags["History"])

	// Add a new item which expires the previous item
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Bar")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Bar"}, cache.History)
	tag = fmt.Sprintf("MyAccount:Bar,%d", now)
	assert.NotContains(t, "History", c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Bar"].Tags["History"])

	// Add the same item again
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Bar")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// Basic tests with two items in the History slice
	sr.historyLimit = 2
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// this should be a no-op
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// reorder args
	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Baz")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Baz",
		"arn:aws:iam::123456789012:role/Foo"}, cache.History)

	c.AddHistory(sr, "arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Baz"}, cache.History)

	assert.Contains(t, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags, "History")
}

func (suite *CacheTestSuite) setupDeleteOldHistory() *Cache {
	c := &Cache{
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

	sr := &mockSettingsReader{historyLimit: 2, historyMinutes: 5}

	c := suite.setupDeleteOldHistory()

	// check setup
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// no-op because we haven't timed out yet
	c.deleteOldHistory(sr)
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	c = suite.setupDeleteOldHistory()

	// no-op when HistoryMinutes <= 0
	sr2 := &mockSettingsReader{historyLimit: 1, historyMinutes: 0}
	c.deleteOldHistory(sr2)
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// remove one due to HistoryLimit
	sr2.historyMinutes = 1
	c.deleteOldHistory(sr2)
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
	}, c.GetSSO().History)
	assert.NotContains(t, "History",
		c.SSO["Default"].Roles.Accounts[123456789012].Roles["Foo"].Tags)

	// setup logger for tests
	oldLogger := log.Copy()
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	log = tLogger

	defer func() { log = oldLogger }()

	// remove one because of HistoryMinutes expires
	c = suite.setupDeleteOldHistory()
	sr3 := &mockSettingsReader{historyLimit: 2, historyMinutes: 1}
	c.deleteOldHistory(sr3)

	msg := testlogger.LogMessage{}
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.NotEmpty(t, msg.Message)
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, "Removed expired history role", msg.Message)
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Test"}, c.GetSSO().History)

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam:")
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, "Unable to parse History ARN", msg.Message)

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "but no role by that name")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::1234567890:role/NoHistoryTag")
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "but no account by that name")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["NoHistoryTag"] = &AWSRole{}
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "in history list without a History tag")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo",
		},
	}
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "Too few fields for")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo,kkkk",
		},
	}
	c.deleteOldHistory(sr)
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "Unable to parse")

	tLogger.Reset()
}

// --- query tests ---

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

	_, err := suite.cache.GetRole("arn:aws:2344:role/missing-colon")
	assert.Error(t, err)
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
	aroles = cache.Roles.GetAccountRoles(25823461518)
	assert.Equal(t, 7, len(aroles))
}

func (suite *CacheTestSuite) TestGetAllTags() {
	t := suite.T()
	cache := suite.cache.GetSSO()

	tl := cache.Roles.GetAllTags()
	assert.Equal(t, 10, len(*tl))
	tl = suite.cache.GetAllTagsSelect()
	assert.Equal(t, 10, len(*tl))
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
	assert.Equal(t, int64(12344553243), flat.ExpiresEpoch)

	err = suite.cache.SetRoleExpires(INVALID_ROLE_ARN, 12344553243)
	assert.Error(t, err)
}
