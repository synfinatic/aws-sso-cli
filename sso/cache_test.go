package sso

import (
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
	cache *Cache
}

func TestCacheTestSuite(t *testing.T) {
	settings := &Settings{
		HistoryLimit:   1,
		HistoryMinutes: 90,
	}
	c, _ := OpenCache(TEST_CACHE_FILE, settings)
	s := &CacheTestSuite{
		cache: c,
	}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TestAddHistory() {
	t := suite.T()

	c := &Cache{
		settings: &Settings{
			HistoryLimit:   1,
			HistoryMinutes: 90,
		},
		History: []string{},
		Roles:   &Roles{},
	}

	c.AddHistory("foo")
	assert.Len(t, c.History, 1, 0)
	assert.Contains(t, c.History, "foo")

	c.AddHistory("bar")
	assert.Len(t, c.History, 1)
	assert.Contains(t, c.History, "bar")

	c.settings.HistoryLimit = 2
	c.AddHistory("foo")
	assert.Len(t, c.History, 2)
	assert.Contains(t, c.History, "bar")
	assert.Contains(t, c.History, "foo")

	// this should be a no-op
	c.AddHistory("foo")
	assert.Len(t, c.History, 2)
	assert.Contains(t, c.History, "foo")
	assert.Contains(t, c.History, "bar")
}

func (suite *CacheTestSuite) TestExpired() {
	t := suite.T()
	assert.NotNil(t, suite.cache.Expired(nil))
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

	ids := suite.cache.Roles.AccountIds()
	assert.Equal(t, 4, len(ids))
}

func (suite *CacheTestSuite) TestGetAllRoles() {
	t := suite.T()

	roles := suite.cache.Roles.GetAllRoles()
	assert.Equal(t, 19, len(roles))

	aroles := suite.cache.Roles.GetAccountRoles(707513610766)
	assert.Equal(t, 4, len(aroles))
	aroles = suite.cache.Roles.GetAccountRoles(502470824893)
	assert.Equal(t, 4, len(aroles))
	aroles = suite.cache.Roles.GetAccountRoles(258234615182)
	assert.Equal(t, 7, len(aroles))
}

func (suite *CacheTestSuite) TestGetAllTags() {
	t := suite.T()
	tl := suite.cache.Roles.GetAllTags()
	assert.Equal(t, 8, len(*tl))
	tl = suite.cache.GetAllTagsSelect()
	assert.Equal(t, 8, len(*tl))
}

func (suite *CacheTestSuite) TestGetRoleTags() {
	t := suite.T()

	rt := suite.cache.Roles.GetRoleTags()
	assert.Equal(t, 19, len(*rt))
	rt = suite.cache.GetRoleTagsSelect()
	assert.Equal(t, 19, len(*rt))
}

func (suite *CacheTestSuite) TestMatchingRoles() {
	t := suite.T()

	match := map[string]string{
		"Type": "Main Account",
		"Foo":  "Bar",
	}
	roles := suite.cache.Roles.MatchingRoles(match)
	assert.Equal(t, 1, len(roles))

	match["Nothing"] = "Matches"
	roles = suite.cache.Roles.MatchingRoles(match)
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
