package sso

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type CacheTestSuite struct {
	suite.Suite
}

func TestCacheTestSuite(t *testing.T) {
	s := &CacheTestSuite{}
	suite.Run(t, s)
}

func (suite *CacheTestSuite) TestAddHistory() {
	t := suite.T()

	c := &Cache{
		History: []string{},
		Roles:   &Roles{},
	}

	c.AddHistory("foo", 1)
	assert.Len(t, c.History, 1)
	assert.Contains(t, c.History, "foo")

	c.AddHistory("bar", 1)
	assert.Len(t, c.History, 1)
	assert.Contains(t, c.History, "bar")

	c.AddHistory("foo", 2)
	assert.Len(t, c.History, 2)
	assert.Contains(t, c.History, "bar")
	assert.Contains(t, c.History, "foo")

	// this should be a no-op
	c.AddHistory("foo", 2)
	assert.Len(t, c.History, 2)
	assert.Contains(t, c.History, "foo")
	assert.Contains(t, c.History, "bar")
}
