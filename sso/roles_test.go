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
	"math"
	"os"
	"strings"
	"testing"
	"time"

	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

const (
	TEST_JSON_STORE_FILE = "../internal/storage/testdata/store.json"
	TEST_ROLES_TEST_FILE = "./testdata/roles_tests.yaml"
)

type CacheRolesTestSuite struct {
	suite.Suite
	cache     *Cache
	cacheFile string
	settings  *Settings
	storage   storage.SecureStorage
	jsonFile  string
}

func TestCacheRolesTestSuite(t *testing.T) {
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

	// cache
	input, err := os.ReadFile(TEST_CACHE_FILE)
	assert.NoError(t, err)

	err = os.WriteFile(f.Name(), input, 0600)
	assert.NoError(t, err)

	c, err := OpenCache(f.Name(), settings)
	assert.NoError(t, err)

	// secure store
	f2, err := os.CreateTemp("", "*")
	assert.Nil(t, err)

	jsonFile := f2.Name()
	f2.Close()

	input, err = os.ReadFile(TEST_JSON_STORE_FILE)
	assert.Nil(t, err)

	err = os.WriteFile(jsonFile, input, 0600)
	assert.Nil(t, err)

	sstore, err := storage.OpenJsonStore(jsonFile)
	assert.Nil(t, err)

	defaults := map[string]interface{}{}
	over := OverrideSettings{}
	set, err := LoadSettings(TEST_SETTINGS_FILE, TEST_CACHE_FILE, defaults, over)
	assert.NoError(t, err)

	s := &CacheRolesTestSuite{
		cache:     c,
		cacheFile: f.Name(),
		settings:  set,
		storage:   sstore,
		jsonFile:  jsonFile,
	}
	suite.Run(t, s)
}

func (suite *CacheRolesTestSuite) TearDownAllSuite() {
	os.Remove(suite.cacheFile)
	os.Remove(suite.jsonFile)
}

func (suite *CacheRolesTestSuite) TestAccountIds() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles

	assert.NotEmpty(t, roles.AccountIds())
	assert.Contains(t, roles.AccountIds(), int64(25823461518))
	assert.NotContains(t, roles.AccountIds(), int64(2582346))
}

func (suite *CacheRolesTestSuite) TestGetAllRoles() {
	t := suite.T()

	roles := suite.cache.SSO[suite.cache.ssoName].Roles
	flat := roles.GetAllRoles()
	assert.NotEmpty(t, flat)
}

func (suite *CacheRolesTestSuite) TestGetAccountRoles() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles

	flat := roles.GetAccountRoles(25823461518)
	assert.NotEmpty(t, flat)

	flat = roles.GetAccountRoles(258234615)
	assert.Empty(t, flat)
}

func (suite *CacheRolesTestSuite) TestGetAllTags() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles

	tags := *(roles.GetAllTags())
	assert.NotEmpty(t, tags)
	assert.Contains(t, tags["Email"], "control-tower-dev-aws@ourcompany.com")
	assert.NotContains(t, tags["Email"], "foobar@ourcompany.com")
}

func (suite *CacheRolesTestSuite) TestGetRoleTags() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles

	tags := *(roles.GetRoleTags())
	assert.NotEmpty(t, tags)
	arn := "arn:aws:iam::025823461518:role/AWSAdministratorAccess"
	assert.Contains(t, tags, arn)
	assert.NotContains(t, tags, "foobar")
	assert.Contains(t, tags[arn]["Email"], "control-tower-dev-aws@ourcompany.com")
	assert.NotContains(t, tags[arn]["Email"], "foobar@ourcompany.com")
}

func (suite *CacheRolesTestSuite) TestGetRole() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles

	_, err := roles.GetRole(58234615182, "AWSAdministratorAccess")
	assert.Error(t, err)

	r, err := roles.GetRole(25823461518, "AWSAdministratorAccess")
	assert.NoError(t, err)
	assert.Equal(t, int64(25823461518), r.AccountId)
	assert.Equal(t, "AWSAdministratorAccess", r.RoleName)
	assert.Equal(t, "", r.Profile)
	assert.Equal(t, "us-east-1", r.DefaultRegion)
	assert.Equal(t, "", r.Via)
	p, err := r.ProfileName(suite.settings)
	assert.NoError(t, err)
	assert.Equal(t, "OurCompany Control Tower Playground/AWSAdministratorAccess", p)
}

func (suite *CacheRolesTestSuite) TestProfileName() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles
	r, err := roles.GetRole(25823461518, "AWSAdministratorAccess")
	assert.NoError(t, err)

	p, err := r.ProfileName(suite.settings)
	assert.NoError(t, err)
	assert.Equal(t, "OurCompany Control Tower Playground/AWSAdministratorAccess", p)

	settings := suite.settings
	settings.ProfileFormat = `{{ FirstItem .AccountName .AccountAlias | StringReplace " " "_" }}:{{ .RoleName }}`
	p, err = r.ProfileName(settings)
	assert.NoError(t, err)
	assert.Equal(t, "OurCompany_Control_Tower_Playground:AWSAdministratorAccess", p)

	settings.ProfileFormat = `{{ FirstItem .AccountName .AccountAlias | StringReplace " " "_" | lower }}:{{ .RoleName | upper }}`
	p, err = r.ProfileName(settings)
	assert.NoError(t, err)
	assert.Equal(t, "ourcompany_control_tower_playground:AWSADMINISTRATORACCESS", p)
}

func (suite *CacheRolesTestSuite) TestGetRoleByProfile() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles
	flat, err := roles.GetRoleByProfile("audit-admin", suite.settings)
	assert.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::502470824893:role/AWSAdministratorAccess", flat.Arn)

	_, err = roles.GetRoleByProfile("foobar", suite.settings)
	assert.Error(t, err)

	flat, err = roles.GetRoleByProfile("Dev Account/AWSReadOnlyAccess", suite.settings)
	assert.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::707513610766:role/AWSReadOnlyAccess", flat.Arn)
}

func (suite *CacheRolesTestSuite) TestGetEnvVarTags() {
	t := suite.T()
	roles := suite.cache.SSO[suite.cache.ssoName].Roles
	flat, err := roles.GetRoleByProfile("audit-admin", suite.settings)
	assert.NoError(t, err)

	settings := Settings{
		EnvVarTags: []string{
			"Role",
			"Email",
			"AccountName",
			"FooBar", // doesn't exist
		},
	}

	x := map[string]string{
		"AWS_SSO_TAG_ROLE":        "AWSAdministratorAccess",
		"AWS_SSO_TAG_EMAIL":       "control-tower-dev-aws+audit@ourcompany.com",
		"AWS_SSO_TAG_ACCOUNTNAME": "Audit",
	}
	assert.Equal(t, x, flat.GetEnvVarTags(&settings))
}

func TestAWSRoleFlatGetSortableField(t *testing.T) {
	flat := AWSRoleFlat{
		RoleName:     "foobar",
		AccountId:    12344553243,
		AccountIdPad: "012344553243",
		ExpiresEpoch: 0,
		Expires:      "Expired",
	}

	f, err := flat.GetSortableField("RoleName")
	assert.NoError(t, err)
	assert.Equal(t, Sval, f.Type)
	assert.Equal(t, "foobar", f.Sval)

	f, err = flat.GetSortableField("AccountId")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(12344553243), f.Ival)

	f, err = flat.GetSortableField("AccountIdPad")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(12344553243), f.Ival)

	f, err = flat.GetSortableField("Expires")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(math.Pow(2, 62)), f.Ival)

	f, err = flat.GetSortableField("ExpiresEpoch")
	assert.NoError(t, err)
	assert.Equal(t, Ival, f.Type)
	assert.Equal(t, int64(math.Pow(2, 62)), f.Ival)

	f, err = flat.GetSortableField("Tags")
	assert.Error(t, err)

	f, err = flat.GetSortableField("Role")
	assert.Error(t, err)
}

func TestAWSRoleFlatGetHeader(t *testing.T) {
	f := AWSRoleFlat{}
	x, err := f.GetHeader("Expires")
	assert.NoError(t, err)
	assert.Equal(t, "Expires", x)

	x, err = f.GetHeader("ExpiresEpoch")
	assert.NoError(t, err)
	assert.Equal(t, "ExpiresEpoch", x)

	x, err = f.GetHeader("Id")
	assert.NoError(t, err)
	assert.Equal(t, "Id", x)

	x, err = f.GetHeader("Tags")
	assert.NoError(t, err)
	assert.Equal(t, "", x)
}

func TestAWSRoleFlatExpired(t *testing.T) {
	f := &AWSRoleFlat{
		ExpiresEpoch: 0,
	}
	assert.True(t, f.IsExpired())

	f = &AWSRoleFlat{
		ExpiresEpoch: 12345455,
	}
	assert.True(t, f.IsExpired())

	f = &AWSRoleFlat{
		ExpiresEpoch: time.Now().Add(time.Minute * 5).Unix(),
	}
	assert.False(t, f.IsExpired())
}

func TestAWSRoleFlatProfileName(t *testing.T) {
	s := &Settings{
		ProfileFormat: "{{ what }}",
	}

	f := &AWSRoleFlat{}
	_, err := f.ProfileName(s)
	assert.Error(t, err)
}

// profile functions
func TestEmptyString(t *testing.T) {
	assert.True(t, emptyString(""))
	assert.False(t, emptyString("foo"))
}

func TestFirstItem(t *testing.T) {
	assert.Equal(t, "x", firstItem("x", "b"))
	assert.Equal(t, "x", firstItem("x"))
	assert.Equal(t, "x", firstItem("", "x", "b"))
	assert.Equal(t, "", firstItem())
}

func TestStringReplace(t *testing.T) {
	assert.Equal(t, "aaaaa", stringReplace("b", "a", "bbbbb"))
	assert.Equal(t, "zaaaaax", stringReplace("b", "a", "zbbbbbx"))
}

func TestStringsJoin(t *testing.T) {
	assert.Equal(t, "a.b.c", stringsJoin(".", "a", "b", "c"))
}

func TestAWSRoleFlatHasPrefix(t *testing.T) {
	f := &AWSRoleFlat{
		Id:            10,
		AccountId:     555555,
		AccountName:   "testing account",
		AccountAlias:  "testing",
		EmailAddress:  "testing+aws@company.com",
		Arn:           "arn:aws:iam::555555:role/Testing",
		RoleName:      "Testing",
		DefaultRegion: "us-east-1",
		Profile:       "Testing",
		SSO:           "Main",
		SSORegion:     "us-west-2",
		StartUrl:      "https://test.awsapps.com/start",
		Via:           "arn:aws:iam::555555:role/Foobar",
	}

	// invalid key
	invalid := map[string]string{
		"X":            "test",
		"Expires":      "foo",
		"ExpiresEpoch": "bar",
		"Tags":         "baz",
	}
	for k, v := range invalid {
		_, err := f.HasPrefix(k, v)
		assert.Error(t, err)
	}

	valid := map[string]string{
		"Id":            "1",
		"AccountId":     "55",
		"AccountName":   "testing",
		"AccountAlias":  "test",
		"EmailAddress":  "testing+aws@company.",
		"Arn":           "arn:aws",
		"RoleName":      "Test",
		"DefaultRegion": "us-",
		"Profile":       "T",
		"SSO":           "Ma",
		"SSORegion":     "us-we",
		"StartUrl":      "https",
		"Via":           "arn:",
	}

	for k, v := range valid {
		if k == "Via" {
			log.Errorf("%s = %s", k, v)
		}
		ret, err := f.HasPrefix(k, v)
		assert.NoError(t, err)
		assert.True(t, ret)
	}

	falseValues := map[string]string{
		"Id":           "55",
		"EmailAddress": "bingo",
		"SSO":          "wtf?",
		"StartUrl":     "123344",
	}

	for k, v := range falseValues {
		ret, err := f.HasPrefix(k, v)
		assert.NoError(t, err)
		assert.False(t, ret)
	}

	v, err := f.HasPrefix("Via", "x")
	assert.NoError(t, err)
	assert.False(t, v)
}

func (suite *CacheRolesTestSuite) TestCheckProfiles() {
	t := suite.T()
	tests := ProfileTests{}

	data, err := os.ReadFile(TEST_ROLES_TEST_FILE)
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

	badSettings.ProfileFormat = "{{ .InvalidFormat }}"
	r = tests["Valid3"]
	err = r.checkProfiles(&badSettings)
	assert.Error(t, err)
}
