package sso

import (
	"os"
	"testing"

	yaml "github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RoleTagsTestSuite struct {
	suite.Suite
	File TestRoleFile
}

type TestRoleFile struct {
	GetMatchingRoles       *map[string]TestEntry               `yaml:"GetMatchingRoles"`
	UsefulTags             *map[string]TestEntry               `yaml:"UsefulTags"`
	GetPossibleUniqueRoles *map[string]TestPossibleUniqueEntry `yaml:"GetPossibleUniqueRoles"`
	GetMatchCount          *map[string]TestIntEntry            `yaml:"GetMatchCount"`
	GetRoleTags            *map[string]TestRolesEntry          `yaml:"GetRoleTags"`
}

type TestEntry struct {
	Query    *map[string]string `yaml:"Query"`
	Result   *[]string          `yaml:"Result"`
	RoleTags *RoleTags          `yaml:"RoleTags"`
}

type TestPossibleUniqueEntry struct {
	Query       *map[string]string `yaml:"Query"`
	QueryKey    string             `yaml:"QueryKey"`
	QueryValues *[]string          `yaml:"QueryValues"`
	Result      *[]string          `yaml:"Result"`
	RoleTags    *RoleTags          `yaml:"RoleTags"`
}

type TestIntEntry struct {
	Query    *map[string]string `yaml:"Query"`
	Result   int                `yaml:"Result"`
	RoleTags *RoleTags          `yaml:"RoleTags"`
}

type TestRolesEntry struct {
	Query    string             `yaml:"Query"`
	Result   *map[string]string `yaml:"Result"`
	RoleTags *RoleTags          `yaml:"RoleTags"`
}

const (
	TEST_ROLE_TAGS_FILE = "./testdata/role_tags.yaml"
)

func TestRoleTagsTestSuite(t *testing.T) {
	info, err := os.Stat(TEST_ROLE_TAGS_FILE)
	if err != nil {
		log.WithError(err).Fatalf("os.Stat %s", TEST_ROLE_TAGS_FILE)
	}

	file, err := os.Open(TEST_ROLE_TAGS_FILE)
	if err != nil {
		log.WithError(err).Fatalf("os.Open %s", TEST_ROLE_TAGS_FILE)
	}

	defer file.Close()

	buf := make([]byte, info.Size())
	_, err = file.Read(buf)
	if err != nil {
		log.WithError(err).Fatalf("Error reading %d bytes from %s", info.Size(), TEST_ROLE_TAGS_FILE)
	}

	s := &RoleTagsTestSuite{}
	err = yaml.Unmarshal(buf, &s.File)
	if err != nil {
		log.WithError(err).Fatalf("Failed parsing %s", TEST_ROLE_TAGS_FILE)
	}

	suite.Run(t, s)
}

func (suite *RoleTagsTestSuite) TestGetMatchingRoles() {
	t := suite.T()

	f := (*suite).File
	for testName, test := range *f.GetMatchingRoles {
		ret := test.RoleTags.GetMatchingRoles(*test.Query)
		assert.ElementsMatch(t, *test.Result, ret, testName)
	}
}

func (suite *RoleTagsTestSuite) TestUsefulTags() {
	t := suite.T()

	f := (*suite).File
	for testName, test := range *f.UsefulTags {
		ret := test.RoleTags.UsefulTags(*test.Query)
		assert.ElementsMatch(t, *test.Result, ret, testName)
	}
}

func (suite *RoleTagsTestSuite) TestGetPossibleUniqueRoles() {
	t := suite.T()

	f := (*suite).File
	for testName, test := range *f.GetPossibleUniqueRoles {
		ret := test.RoleTags.GetPossibleUniqueRoles(*test.Query, test.QueryKey, *test.QueryValues)
		assert.ElementsMatch(t, *test.Result, ret, testName)
	}
}

func (suite *RoleTagsTestSuite) TestGetMatchCount() {
	t := suite.T()

	f := (*suite).File
	for testName, test := range *f.GetMatchCount {
		ret := test.RoleTags.GetMatchCount(*test.Query)
		assert.Equal(t, test.Result, ret, testName)
	}

}

func (suite *RoleTagsTestSuite) TestGetRoleTags() {
	t := suite.T()

	f := (*suite).File
	for testName, test := range *f.GetRoleTags {
		ret := test.RoleTags.GetRoleTags(test.Query)
		assert.Equal(t, *test.Result, ret, testName)
	}
}
