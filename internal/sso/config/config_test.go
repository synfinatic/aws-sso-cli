package config

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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

func TestGetRoleMatches(t *testing.T) {
	accounts := map[string]*SSOAccount{
		"123456789012": {
			Tags: map[string]string{
				"Foo": "foo",
				"Bar": "bar",
			},
			Name: "MyAccount",
		},
	}
	roles := map[string]*SSORole{
		"FirstRole": {
			account: accounts["123456789012"],
			ARN:     "arn:aws:iam::123456789012:role/FirstRole",
			Tags: map[string]string{
				"Hello": "There",
			},
		},
		"SecondRole": {
			account: accounts["123456789012"],
			ARN:     "arn:aws:iam::123456789012:role/SecondRole",
			Tags: map[string]string{
				"Yes": "Please",
			},
		},
	}
	accounts["123456789012"].Roles = roles
	s := &SSOConfig{
		Accounts: accounts,
	}

	none := map[string]string{
		"No": "Hits",
	}
	empty := s.GetRoleMatches(none)
	assert.Empty(t, empty)

	twohits := map[string]string{
		"Foo": "foo",
		"Bar": "bar",
	}
	two := s.GetRoleMatches(twohits)
	assert.Equal(t, 2, len(two))

	onehit := map[string]string{
		"Hello": "There",
	}
	one := s.GetRoleMatches(onehit)
	assert.Equal(t, 1, len(one))

	yes := accounts["123456789012"].HasRole("arn:aws:iam::123456789012:role/FirstRole")
	assert.True(t, yes)

	no := accounts["123456789012"].HasRole("arn:aws:iam::123456789012:role/MissingRole")
	assert.False(t, no)
}

func TestRefresh(t *testing.T) {
	params := SSOConfigSettings{
		UrlAction:  uri.Open,
		MaxBackoff: 60,
		MaxRetry:   3,
	}

	c := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": nil,
			"023456789012": {
				Roles: map[string]*SSORole{
					"FooBar0": nil,
				},
			},
			"33456789012": {
				Roles: map[string]*SSORole{
					"FooBar3": nil,
				},
			},
		},
	}
	c.Refresh(params) // no crash
	assert.Equal(t, SSOAccount{config: c}, *(c.Accounts["123456789012"]))

	assert.Equal(t, c.AuthUrlAction, uri.Open)
	assert.Equal(t, c.MaxBackoff, 60)
	assert.Equal(t, c.MaxRetry, 3)

	c.Accounts["123456789012"].Roles = map[string]*SSORole{}
	c.Accounts["123456789012"].Roles["FooBar"] = nil

	c.Refresh(params) // no crash
	assert.Equal(t, *(c.Accounts["123456789012"].Roles["FooBar"]), SSORole{
		ARN:     "arn:aws:iam::123456789012:role/FooBar",
		account: c.Accounts["123456789012"],
	})

	// test that the refresh function doesn't remove accounts, but does
	// standardize with leading zeros
	assert.Contains(t, c.Accounts, "123456789012")
	assert.Contains(t, c.Accounts, "023456789012")
	assert.Contains(t, c.Accounts, "033456789012")
}

func TestGetRole(t *testing.T) {
	c := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": {
				Roles: map[string]*SSORole{},
			},
			"023456789012": {
				Roles: map[string]*SSORole{
					"FooBar0": {},
				},
			},
			"33456789012": {
				Roles: map[string]*SSORole{
					"FooBar3": {},
				},
			},
		},
	}

	_, err := c.GetRole(123456789012, "FooBar0")
	assert.Error(t, err)

	r, err := c.GetRole(23456789012, "FooBar0")
	assert.NoError(t, err)
	assert.NotNil(t, r)
}

func TestGetKeySetKey(t *testing.T) {
	c := &SSOConfig{}
	assert.Empty(t, c.GetKey())
	c.SetKey("MySSO")
	assert.Equal(t, "MySSO", c.GetKey())
}

func TestGetConfigFileSetConfigFile(t *testing.T) {
	c := &SSOConfig{}
	assert.Empty(t, c.GetConfigFile())
	c.SetConfigFile("/tmp/test.yaml")
	assert.Equal(t, "/tmp/test.yaml", c.GetConfigFile())
}

func TestCreatedAt(t *testing.T) {
	f, err := os.CreateTemp("", "ssoconfig-*.yaml")
	assert.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	before := time.Now().Unix()
	c := &SSOConfig{}
	c.SetConfigFile(f.Name())
	ts := c.CreatedAt()
	after := time.Now().Unix()

	assert.GreaterOrEqual(t, ts, before)
	assert.LessOrEqual(t, ts, after)
}

func TestGetRoles(t *testing.T) {
	account := &SSOAccount{
		Roles: map[string]*SSORole{
			"Alpha": {ARN: "arn:aws:iam::123456789012:role/Alpha"},
			"Beta":  {ARN: "arn:aws:iam::123456789012:role/Beta"},
		},
	}
	c := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": account,
		},
	}
	roles := c.GetRoles()
	assert.Len(t, roles, 2)
}

func TestSSOConfigGetAllTags(t *testing.T) {
	account := &SSOAccount{
		Name: "MyAccount",
	}
	role := &SSORole{
		account: account,
		ARN:     "arn:aws:iam::123456789012:role/MyRole",
		Tags:    map[string]string{"Env": "prod"},
	}
	account.Roles = map[string]*SSORole{"MyRole": role}
	c := &SSOConfig{
		Accounts: map[string]*SSOAccount{"123456789012": account},
	}
	tl := c.GetAllTags()
	assert.NotNil(t, tl)
	envVals, ok := (*tl)["Env"]
	assert.True(t, ok)
	assert.Contains(t, envVals, "prod")
}

func TestGetConfigHash(t *testing.T) {
	c := &SSOConfig{
		Accounts: map[string]*SSOAccount{
			"123456789012": {
				Roles: map[string]*SSORole{
					"MyRole": {Tags: map[string]string{"k": "v"}},
				},
			},
		},
	}
	h1 := c.GetConfigHash("format-a")
	h2 := c.GetConfigHash("format-a")
	h3 := c.GetConfigHash("format-b")
	assert.Equal(t, h1, h2)
	assert.NotEqual(t, h1, h3)
	assert.Len(t, h1, 64) // hex-encoded SHA256
}

func TestSSOAccountGetAllTags(t *testing.T) {
	a := &SSOAccount{
		Name:          "My Account",
		DefaultRegion: "us-west-2",
		Tags:          map[string]string{"Team": "ops"},
	}
	tags := a.GetAllTags(123456789012)
	assert.Equal(t, "My_Account", tags["AccountName"])
	assert.Equal(t, "123456789012", tags["AccountId"])
	assert.Equal(t, "us-west-2", tags["DefaultRegion"])
	assert.Equal(t, "ops", tags["Team"])

	// zero id: AccountId tag not set
	tagsNoId := a.GetAllTags(0)
	_, hasId := tagsNoId["AccountId"]
	assert.False(t, hasId)

	// unnamed: falls back to *Unknown*
	aUnnamed := &SSOAccount{}
	tagsUnnamed := aUnnamed.GetAllTags(0)
	assert.Equal(t, "*Unknown*", tagsUnnamed["AccountName"])
}

func TestSSORoleGetRoleName(t *testing.T) {
	r := &SSORole{ARN: "arn:aws:iam::123456789012:role/MyRole"}
	assert.Equal(t, "MyRole", r.GetRoleName())
}

func TestSSORoleGetAccountId(t *testing.T) {
	r := &SSORole{ARN: "arn:aws:iam::123456789012:role/MyRole"}
	assert.Equal(t, "123456789012", r.GetAccountId())
}

func TestSSORoleGetAccountId64(t *testing.T) {
	r := &SSORole{ARN: "arn:aws:iam::123456789012:role/MyRole"}
	assert.Equal(t, int64(123456789012), r.GetAccountId64())
}

func TestSSORoleGetAllTags(t *testing.T) {
	account := &SSOAccount{
		Name: "MyAccount",
		Tags: map[string]string{"Env": "staging"},
	}
	role := &SSORole{
		account:       account,
		ARN:           "arn:aws:iam::123456789012:role/MyRole",
		DefaultRegion: "eu-west-1",
		Tags:          map[string]string{"Team": "infra"},
	}
	tags := role.GetAllTags()
	assert.Equal(t, "MyRole", tags["RoleName"])
	assert.Equal(t, "123456789012", tags["AccountId"])
	assert.Equal(t, "eu-west-1", tags["DefaultRegion"])
	assert.Equal(t, "infra", tags["Team"])
	assert.Equal(t, "staging", tags["Env"])
	assert.Equal(t, "MyAccount", tags["AccountName"])

	// no DefaultRegion: tag absent
	roleNoRegion := &SSORole{
		account: account,
		ARN:     "arn:aws:iam::123456789012:role/Other",
	}
	tagsNoRegion := roleNoRegion.GetAllTags()
	_, hasRegion := tagsNoRegion["DefaultRegion"]
	assert.False(t, hasRegion)
}

func TestRoleInfoRoleArn(t *testing.T) {
	ri := RoleInfo{AccountId: "123456789012", RoleName: "MyRole"}
	assert.Equal(t, "arn:aws:iam::123456789012:role/MyRole", ri.RoleArn())
}

func TestRoleInfoGetAccountId64(t *testing.T) {
	ri := RoleInfo{AccountId: "123456789012"}
	assert.Equal(t, int64(123456789012), ri.GetAccountId64())
}

func TestRoleInfoGetHeader(t *testing.T) {
	ri := RoleInfo{}
	h, err := ri.GetHeader("RoleName")
	assert.NoError(t, err)
	assert.Equal(t, "RoleName", h)

	_, err = ri.GetHeader("NonExistentField")
	assert.Error(t, err)
}

func TestAccountInfoGetAccountId64(t *testing.T) {
	ai := AccountInfo{AccountId: "123456789012"}
	assert.Equal(t, int64(123456789012), ai.GetAccountId64())
}

func TestAccountInfoGetHeader(t *testing.T) {
	ai := AccountInfo{}
	h, err := ai.GetHeader("AccountName")
	assert.NoError(t, err)
	assert.Equal(t, "AccountName", h)

	_, err = ai.GetHeader("NonExistentField")
	assert.Error(t, err)
}
