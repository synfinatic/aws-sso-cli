package utils

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type UtilsTestSuite struct {
	suite.Suite
}

func TestUtilsSuite(t *testing.T) {
	s := &UtilsTestSuite{}
	suite.Run(t, s)
}

func (suite *UtilsTestSuite) TestParseRoleARN() {
	t := suite.T()

	a, r, err := ParseRoleARN("arn:aws:iam:11111:role/Foo")
	assert.Equal(t, int64(11111), a)
	assert.Equal(t, "Foo", r)
	assert.Nil(t, err)

	_, _, err = ParseRoleARN("")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("arnFoo")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam:a:role/Foo")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam:000000011111:role")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("aws:iam:000000011111:role/Foo")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("invalid:arn:aws:iam:000000011111:role/Foo")
	assert.NotNil(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam:000000011111:role/Foo/Bar")
	assert.NotNil(t, err)
}

func (suite *UtilsTestSuite) TestMakeRoleARN() {
	t := suite.T()

	assert.Equal(t, "arn:aws:iam:000000011111:role/Foo", MakeRoleARN(11111, "Foo"))
	assert.Equal(t, "arn:aws:iam:000000711111:role/Foo", MakeRoleARN(711111, "Foo"))
	assert.Equal(t, "arn:aws:iam:000000000000:role/", MakeRoleARN(0, ""))
}

func (suite *UtilsTestSuite) TestEnsureDirExists() {
	t := suite.T()

	assert.Nil(t, EnsureDirExists("./testdata/role_tags.yaml"))
	assert.NotNil(t, EnsureDirExists("./does_not_exist_dir/foo.yaml"))
	defer os.Remove("./does_not_exist_dir")
}

func (suite *UtilsTestSuite) TestGetHomePath() {
	t := suite.T()

	assert.Equal(t, "/", GetHomePath("/"))
	assert.Equal(t, ".", GetHomePath("."))
	assert.Equal(t, "/foo/bar", GetHomePath("/foo/bar"))
	assert.Equal(t, "/foo/bar", GetHomePath("/foo////bar"))
	assert.Equal(t, "/bar", GetHomePath("/foo/../bar"))
	home, _ := os.UserHomeDir()
	x := filepath.Join(home, "foo/bar")
	assert.Equal(t, x, GetHomePath("~/foo/bar"))
}
