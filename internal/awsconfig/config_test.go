package awsconfig

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
	"github.com/synfinatic/aws-sso-cli/internal/sso"
)

func TestAwsConfigFile(t *testing.T) {
	assert.Equal(t, "/dev/null", AwsConfigFile("/dev/null"))

	os.Setenv("AWS_CONFIG_FILE", "/foo/bar")
	assert.Equal(t, "/foo/bar", AwsConfigFile(""))

	os.Unsetenv("AWS_CONFIG_FILE")
	test := fileutils.GetHomePath("~/.foo.bar")
	assert.Equal(t, test, AwsConfigFile("~/.foo.bar"))

	assert.Equal(t, fileutils.GetHomePath("~/.aws/config"), AwsConfigFile(""))
}

func TestGetProfileMap(t *testing.T) {
	s := &sso.Settings{
		Cache: &sso.Cache{
			SSO: map[string]*sso.SSOCache{
				"Default": {
					Roles: &sso.Roles{
						Accounts: map[int64]*sso.AWSAccount{
							12345: {
								Alias: "test",
								Name:  "testing",
								Roles: map[string]*sso.AWSRole{
									"Foo": {
										Arn: "aws:arn:iam::12345:role/Foo",
									},
									"Bar": {
										Arn: "aws:arn:iam::12345:role/Bar",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	profiles, err := getProfileMap("Default", s)
	assert.NoError(t, err)
	p := *profiles
	assert.Equal(t, 1, len(p))
	assert.Equal(t, 2, len(p["Default"]))

	// Check when the SSO name is not available we should get an empty map
	profiles, err = getProfileMap("NotAvailable", s)
	assert.NoError(t, err)
	p = *profiles
	assert.Equal(t, 0, len(p))

	// now fail
	s.Cache.SSO["Other"] = &sso.SSOCache{
		Roles: &sso.Roles{
			Accounts: map[int64]*sso.AWSAccount{
				12345: {
					Alias: "test",
					Name:  "testing",
					Roles: map[string]*sso.AWSRole{
						"Foo": {
							Arn: "aws:arn:iam::12345:role/Foo",
						},
					},
				},
			},
		},
	}
	_, err = getProfileMap("Default", s)
	assert.Error(t, err)
}

func TestPrintAwsConfig(t *testing.T) {
	s := &sso.Settings{
		Cache: &sso.Cache{
			SSO: map[string]*sso.SSOCache{
				"Default": {
					Roles: &sso.Roles{
						Accounts: map[int64]*sso.AWSAccount{
							12345: {
								Alias: "test",
								Name:  "testing",
								Roles: map[string]*sso.AWSRole{
									"Foo": {
										Arn: "aws:arn:iam::12345:role/Foo",
									},
									"Bar": {
										Arn: "aws:arn:iam::12345:role/Bar",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	var err error
	stdout, err = os.CreateTemp("", "")
	assert.NoError(t, err)
	fname := stdout.Name()
	defer os.Remove(fname)

	err = PrintAwsConfig("Default", s)
	assert.NoError(t, err)

	_, err = stdout.Seek(0, 0)
	assert.NoError(t, err)

	buf := make([]byte, 1024*1024)
	len, err := stdout.ReadAt(buf, 0)
	assert.Error(t, err)
	assert.Less(t, 300, len)
	assert.Contains(t, string(buf), "[profile 000000012345:Bar]")
	assert.Regexp(t, regexp.MustCompile(`credential_process = /[^ ]+/awsconfig.test -S "Default" process --arn aws:arn:iam::12345:role/Bar`), string(buf))
	assert.Regexp(t, regexp.MustCompile(`# BEGIN_AWS_SSO_CLI`), string(buf))
	assert.Regexp(t, regexp.MustCompile(`# END_AWS_SSO_CLI`), string(buf))
	stdout.Close()

	// now fail
	s.Cache.SSO["Other"] = &sso.SSOCache{
		Roles: &sso.Roles{
			Accounts: map[int64]*sso.AWSAccount{
				12345: {
					Alias: "test",
					Name:  "testing",
					Roles: map[string]*sso.AWSRole{
						"Foo": {
							Arn: "aws:arn:iam::12345:role/Foo",
						},
					},
				},
			},
		},
	}

	err = PrintAwsConfig("Default", s)
	assert.Error(t, err)
}

func TestUpdateAwsConfig(t *testing.T) {
	s := &sso.Settings{
		Cache: &sso.Cache{
			SSO: map[string]*sso.SSOCache{
				"Default": {
					Roles: &sso.Roles{
						Accounts: map[int64]*sso.AWSAccount{
							12345: {
								Alias: "test",
								Name:  "testing",
								Roles: map[string]*sso.AWSRole{
									"Foo": {
										Arn: "aws:arn:iam::12345:role/Foo",
									},
									"Bar": {
										Arn: "aws:arn:iam::12345:role/Bar",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	fname := stdout.Name()
	defer os.Remove(fname)
	cfile.Close()

	err = UpdateAwsConfig("Default", s, fname, false, true)
	assert.NoError(t, err)

	cfile, err = os.Open(fname)
	assert.NoError(t, err)

	buf := make([]byte, 1024*1024)
	len, err := cfile.Read(buf)
	assert.NoError(t, err)
	assert.Less(t, 300, len)
	assert.Contains(t, string(buf), "[profile 000000012345:Bar]")
	assert.Regexp(t, regexp.MustCompile(`credential_process = /[^ ]+/awsconfig.test -S "Default" process --arn aws:arn:iam::12345:role/Bar`), string(buf))
	assert.Regexp(t, regexp.MustCompile(`# BEGIN_AWS_SSO_CLI`), string(buf))
	assert.Regexp(t, regexp.MustCompile(`# END_AWS_SSO_CLI`), string(buf))

	// now fail
	s.Cache.SSO["Other"] = &sso.SSOCache{
		Roles: &sso.Roles{
			Accounts: map[int64]*sso.AWSAccount{
				12345: {
					Alias: "test",
					Name:  "testing",
					Roles: map[string]*sso.AWSRole{
						"Foo": {
							Arn: "aws:arn:iam::12345:role/Foo",
						},
					},
				},
			},
		},
	}

	err = UpdateAwsConfig("Default", s, fname, false, true)
	assert.Error(t, err)
}
