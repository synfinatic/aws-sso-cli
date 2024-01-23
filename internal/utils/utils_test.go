package utils

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"
	"path/filepath"
	"testing"
	"time"

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

	a, r, err := ParseRoleARN("arn:aws:iam::11111:role/Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(11111), a)
	assert.Equal(t, "Foo", r)

	a, r, err = ParseRoleARN("000000011111:Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(11111), a)
	assert.Equal(t, "Foo", r)

	_, _, err = ParseRoleARN("")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arnFoo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::a:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::000000011111:role")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("aws:iam:000000011111:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("invalid:arn:aws:iam::000000011111:role/Foo")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::000000011111:role/Foo/Bar")
	assert.Error(t, err)

	_, _, err = ParseRoleARN("arn:aws:iam::-000000011111:role/Foo")
	assert.Error(t, err)

	// ParseUserARN is just ParseRoleARN...
	a, r, err = ParseUserARN("arn:aws:iam::22222:user/Foo")
	assert.NoError(t, err)
	assert.Equal(t, int64(22222), a)
	assert.Equal(t, "Foo", r)
}

func (suite *UtilsTestSuite) TestMakeRoleARN() {
	t := suite.T()

	assert.Equal(t, "arn:aws:iam::000000011111:role/Foo", MakeRoleARN(11111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARN(711111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:role/", MakeRoleARN(0, ""))

	assert.Panics(t, func() { MakeRoleARN(-1, "foo") })
}

func (suite *UtilsTestSuite) TestMakeUserARN() {
	t := suite.T()

	assert.Equal(t, "arn:aws:iam::000000011111:user/Foo", MakeUserARN(11111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:user/Foo", MakeUserARN(711111, "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:user/", MakeUserARN(0, ""))

	assert.Panics(t, func() { MakeUserARN(-1, "foo") })
}

func (suite *UtilsTestSuite) TestMakeRoleARNs() {
	t := suite.T()

	assert.Equal(t, "arn:aws:iam::000000011111:role/Foo", MakeRoleARNs("11111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARNs("711111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000711111:role/Foo", MakeRoleARNs("000711111", "Foo"))
	assert.Equal(t, "arn:aws:iam::000000000000:role/", MakeRoleARNs("0", ""))

	assert.Panics(t, func() { MakeRoleARNs("asdfasfdo", "foo") })
}

func (suite *UtilsTestSuite) TestEnsureDirExists() {
	t := suite.T()

	defer os.RemoveAll("./does_not_exist_dir")
	assert.NoError(t, EnsureDirExists("./testdata/role_tags.yaml"))
	assert.NoError(t, EnsureDirExists("./does_not_exist_dir/bar/baz/foo.yaml"))

	f, _ := os.OpenFile("./does_not_exist_dir/foo.yaml", os.O_WRONLY|os.O_CREATE, 0644)
	fmt.Fprintf(f, "data")
	f.Close()
	assert.Error(t, EnsureDirExists("./does_not_exist_dir/foo.yaml/bar"))

	_ = os.MkdirAll("./does_not_exist_dir/invalid", 0000)
	assert.Error(t, EnsureDirExists("./does_not_exist_dir/invalid/foo"))

	assert.Error(t, EnsureDirExists("/foo/bar"))
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

func (suite *UtilsTestSuite) TestAccountToString() {
	t := suite.T()

	a, err := AccountIdToString(0)
	assert.NoError(t, err)
	assert.Equal(t, "000000000000", a)

	a, err = AccountIdToString(11111)
	assert.NoError(t, err)
	assert.Equal(t, "000000011111", a)

	a, err = AccountIdToString(999999999999)
	assert.NoError(t, err)
	assert.Equal(t, "999999999999", a)

	_, err = AccountIdToString(-1)
	assert.Error(t, err)

	_, err = AccountIdToString(-19999)
	assert.Error(t, err)

	_, err = AccountIdToString(1000000000000)
	assert.Error(t, err)
}

func (suite *UtilsTestSuite) TestAccountToInt64() {
	t := suite.T()

	_, err := AccountIdToInt64("")
	assert.Error(t, err)

	a, err := AccountIdToInt64("12345")
	assert.NoError(t, err)
	assert.Equal(t, int64(12345), a)

	a, err = AccountIdToInt64("0012345")
	assert.NoError(t, err)
	assert.Equal(t, int64(12345), a)

	_, err = AccountIdToInt64("0012345678912123344455323423423423424")
	assert.Error(t, err)

	_, err = AccountIdToInt64("abdcefgi")
	assert.Error(t, err)

	_, err = AccountIdToInt64("-1")
	assert.Error(t, err)
}

func (suite *UtilsTestSuite) TestParseTimeString() {
	t := suite.T()

	x, e := ParseTimeString("1970-01-01 00:00:00 +0000 GMT")
	assert.NoError(t, e)
	assert.Equal(t, int64(0), x)

	_, e = ParseTimeString("00:00:00 +0000 GMT")
	assert.Error(t, e)
}

func (suite *UtilsTestSuite) TestTimeRemain() {
	t := suite.T()

	x, e := TimeRemain(0, false)
	assert.NoError(t, e)
	assert.Equal(t, "Expired", x)

	d, _ := time.ParseDuration("5m1s")
	future := time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "     5m", x)

	x, e = TimeRemain(future.Unix(), false)
	assert.NoError(t, e)
	assert.Equal(t, "5m", x)

	d, _ = time.ParseDuration("5h5m1s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, " 5h  5m", x)

	x, e = TimeRemain(future.Unix(), false)
	assert.NoError(t, e)
	assert.Equal(t, "5h5m", x)

	// truncate down to < 1min
	d, _ = time.ParseDuration("55s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "   < 1m", x)

	d, _ = time.ParseDuration("25s")
	future = time.Now().Add(d)
	x, e = TimeRemain(future.Unix(), true)
	assert.NoError(t, e)
	assert.Equal(t, "   < 1m", x)
}

func TestStrListContains(t *testing.T) {
	x := []string{"yes", "no"}
	assert.True(t, StrListContains("yes", x))
	assert.False(t, StrListContains("nope", x))
}
