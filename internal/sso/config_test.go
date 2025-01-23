package sso

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/url"
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
	settings := &Settings{
		ProfileFormat: "{{ .AccountIdPad }}:{{ .RoleName }}",
		UrlAction:     url.Open,
		MaxBackoff:    60,
		MaxRetry:      3,
	}

	c := &SSOConfig{
		settings: settings,
		Accounts: map[string]*SSOAccount{
			"123456789012": nil,
		},
	}
	c.Refresh(settings) // no crash
	assert.Equal(t, *(c.Accounts["123456789012"]), SSOAccount{config: c})

	assert.Equal(t, c.AuthUrlAction, url.Open)
	assert.Equal(t, c.MaxBackoff, 60)
	assert.Equal(t, c.MaxRetry, 3)
	assert.Equal(t, c.settings, settings)

	c.Accounts["123456789012"].Roles = map[string]*SSORole{}
	c.Accounts["123456789012"].Roles["FooBar"] = nil

	c.Refresh(settings) // no crash
	assert.Equal(t, *(c.Accounts["123456789012"].Roles["FooBar"]), SSORole{
		ARN:     "arn:aws:iam::123456789012:role/FooBar",
		account: c.Accounts["123456789012"],
	})
}
