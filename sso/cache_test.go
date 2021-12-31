package sso

import (
	"io/ioutil"
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
	cache      *Cache
	configFile string
}

func TestCacheTestSuite(t *testing.T) {
	settings := &Settings{
		HistoryLimit:   1,
		HistoryMinutes: 90,
		DefaultSSO:     "Default",
	}

	// copy our cache test file to a temp file
	f, err := os.CreateTemp("", "*")
	assert.NoError(t, err)
	f.Close()

	input, err := ioutil.ReadFile(TEST_CACHE_FILE)
	assert.NoError(t, err)

	err = ioutil.WriteFile(f.Name(), input, 0600)
	assert.NoError(t, err)

	c, err := OpenCache(f.Name(), settings)
	assert.NoError(t, err)

	s := &CacheTestSuite{
		cache:      c,
		configFile: f.Name(),
	}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TearDownAllSuite() {
	os.Remove(suite.configFile)
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
		Roles:      &Roles{},
	}

	cache := c.GetSSO()
	c.AddHistory("foo")
	assert.Len(t, cache.History, 1, 0)
	assert.Contains(t, cache.History, "foo")

	c.AddHistory("bar")
	assert.Len(t, cache.History, 1)
	assert.Contains(t, cache.History, "bar")

	c.settings.HistoryLimit = 2
	c.AddHistory("foo")
	assert.Len(t, cache.History, 2)
	assert.Contains(t, cache.History, "bar")
	assert.Contains(t, cache.History, "foo")

	// this should be a no-op
	c.AddHistory("foo")
	assert.Len(t, cache.History, 2)
	assert.Contains(t, cache.History, "foo")
	assert.Contains(t, cache.History, "bar")
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
	assert.Equal(t, 8, len(*tl))
	tl = suite.cache.GetAllTagsSelect()
	assert.Equal(t, 8, len(*tl))
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

func (suite *CacheTestSuite) Version() {
	t := suite.T()
	assert.NotEqual(t, CACHE_VERSION, suite.cache.Version)

	err := suite.cache.Save(false)
	assert.NoError(t, err)
	assert.Equal(t, CACHE_VERSION, suite.cache.Version)
}

func (suite *CacheTestSuite) GetSSO() {
	t := suite.T()

	suite.cache.ssoName = "Invalid"
	cache := suite.cache.GetSSO()
	assert.Empty(t, cache.Roles)
	assert.Empty(t, cache.History)
	assert.Equal(t, 0, cache.LastUpdate)

	suite.cache.ssoName = "Default"
	cache = suite.cache.GetSSO()
	assert.NotEmpty(t, cache.Roles)
	assert.Empty(t, cache.History)
	assert.NotEqual(t, 0, cache.LastUpdate)
}
