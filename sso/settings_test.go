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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	TEST_SETTINGS_FILE = "./testdata/settings.yaml"
)

var TEST_GET_ROLE_ARN []string = []string{
	"arn:aws:iam::258234615182:role/AWSAdministratorAccess",
	"arn:aws:iam::258234615182:role/LimitedAccess",
	"arn:aws:iam::833365043586:role/AWSAdministratorAccess",
}

type SettingsTestSuite struct {
	suite.Suite
	settings *Settings
}

func TestSettingsTestSuite(t *testing.T) {
	over := OverrideSettings{}
	defaults := map[string]interface{}{}
	settings, err := LoadSettings(TEST_SETTINGS_FILE, TEST_CACHE_FILE, defaults, over)
	assert.Nil(t, err)

	s := &SettingsTestSuite{
		settings: settings,
	}
	suite.Run(t, s)
}

func (suite *SettingsTestSuite) TestLoadSettings() {
	t := suite.T()

	assert.Equal(t, TEST_SETTINGS_FILE, suite.settings.ConfigFile())
}

func (suite *SettingsTestSuite) TestGetSelectedSSO() {
	t := suite.T()

	sso, err := suite.settings.GetSelectedSSO("Default")
	assert.Nil(t, err)
	assert.Equal(t, "https://d-754545454.awsapps.com/start", sso.StartUrl)

	sso, err = suite.settings.GetSelectedSSO("Foobar")
	assert.NotNil(t, err)
	assert.Equal(t, "", sso.StartUrl)

	sso, err = suite.settings.GetSelectedSSO("")
	assert.Nil(t, err)
	assert.Equal(t, "https://d-754545454.awsapps.com/start", sso.StartUrl)
}

func (suite *SettingsTestSuite) TestCreatedAt() {
	t := suite.T()
	sso, _ := suite.settings.GetSelectedSSO("")
	assert.Equal(t, sso.CreatedAt(), suite.settings.CreatedAt())
}

func (suite *SettingsTestSuite) TestGetRoles() {
	t := suite.T()

	sso, _ := suite.settings.GetSelectedSSO("")
	roles := sso.GetRoles()

	// makes sure we found the 3 roles...
	assert.Equal(t, 3, len(roles))

	// and their ARN's match
	arns := []string{}
	for _, role := range roles {
		arns = append(arns, role.ARN)
	}
	for _, role := range TEST_GET_ROLE_ARN {
		assert.Contains(t, arns, role)
	}
}

func (suite *SettingsTestSuite) TestGetAllTags() {
	t := suite.T()

	sso, _ := suite.settings.GetSelectedSSO("")
	tagsPtr := sso.GetAllTags()
	tags := *tagsPtr
	assert.ElementsMatch(t, tags["Test"], []string{"value", "logs"})
	assert.ElementsMatch(t, tags["Foo"], []string{"Bar", "Moo"})
	assert.ElementsMatch(t, tags["Can"], []string{"Man"})
	assert.ElementsMatch(t, tags["DoesNotExistTag"], []string{})
}

func (suite *SettingsTestSuite) TestSave() {
	t := suite.T()

	dir, err := ioutil.TempDir("", "settings_test")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	p := filepath.Join(dir, "foo/bar/config.yaml")
	err = suite.settings.Save(p, true)
	assert.Nil(t, err)
	err = suite.settings.Save(p, false)
	assert.NotNil(t, err)

	err = suite.settings.Save(dir, false)
	assert.NotNil(t, err)
}

func clearEnv() {
	os.Setenv("AWS_DEFAULT_REGION", "")
	os.Setenv("AWS_SSO_DEFAULT_REGION", "")
}

func (suite *SettingsTestSuite) TestGetDefaultRegion() {
	t := suite.T()

	clearEnv()
	defer clearEnv()

	assert.Equal(t, "ca-central-1", suite.settings.GetDefaultRegion(258234615182, "AWSAdministratorAccess", false))
	assert.Equal(t, "eu-west-1", suite.settings.GetDefaultRegion(258234615182, "LimitedAccess", false))
	assert.Equal(t, "us-east-1", suite.settings.GetDefaultRegion(833365043586, "AWSAdministratorAccess:", false))

	assert.Equal(t, "", suite.settings.GetDefaultRegion(258234615182, "AWSAdministratorAccess", true))
	assert.Equal(t, "", suite.settings.GetDefaultRegion(258234615182, "LimitedAccess", true))
	assert.Equal(t, "", suite.settings.GetDefaultRegion(833365043586, "AWSAdministratorAccess:", true))

	os.Setenv("AWS_DEFAULT_REGION", "us-east-1")
	assert.Equal(t, "", suite.settings.GetDefaultRegion(258234615182, "AWSAdministratorAccess", false))
	assert.Equal(t, "", suite.settings.GetDefaultRegion(258234615182, "LimitedAccess", false))
	assert.Equal(t, "", suite.settings.GetDefaultRegion(833365043586, "AWSAdministratorAccess:", false))

	os.Setenv("AWS_SSO_DEFAULT_REGION", "us-east-1")
	assert.Equal(t, "ca-central-1", suite.settings.GetDefaultRegion(258234615182, "AWSAdministratorAccess", false))
	assert.Equal(t, "eu-west-1", suite.settings.GetDefaultRegion(258234615182, "LimitedAccess", false))
	assert.Equal(t, "us-east-1", suite.settings.GetDefaultRegion(833365043586, "AWSAdministratorAccess:", false))
}

func (suite *SettingsTestSuite) TestOtherSSO() {
	t := suite.T()
	over := OverrideSettings{
		DefaultSSO: "Another",
	}
	defaults := map[string]interface{}{}
	settings, err := LoadSettings(TEST_SETTINGS_FILE, TEST_CACHE_FILE, defaults, over)
	assert.Nil(t, err)

	assert.Equal(t, "us-west-2", settings.GetDefaultRegion(182347455, "AWSAdministratorAccess", false))
}
