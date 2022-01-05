package storage

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateTokenResponseExpired(t *testing.T) {
	tr := &CreateTokenResponse{
		ExpiresAt: 0,
	}
	assert.True(t, tr.Expired())

	tr.ExpiresAt = time.Now().Unix()
	assert.True(t, tr.Expired())

	// one minute buffer
	tr.ExpiresAt = time.Now().Unix() - 61
	assert.True(t, tr.Expired())

	tr.ExpiresAt = time.Now().Unix() + 65
	assert.False(t, tr.Expired())
}

func TestRegisterClientDataExpired(t *testing.T) {
	tr := &RegisterClientData{
		ClientSecretExpiresAt: 0,
	}
	assert.True(t, tr.Expired())

	tr.ClientSecretExpiresAt = time.Now().Unix()
	assert.True(t, tr.Expired())

	// one hour buffer
	tr.ClientSecretExpiresAt = time.Now().Unix() - 60*60 + 1
	assert.True(t, tr.Expired())

	tr.ClientSecretExpiresAt = time.Now().Unix() + 60*60 + 1
	assert.False(t, tr.Expired())
}

func TestRoleCredentialsExpired(t *testing.T) {
	x := RoleCredentials{
		Expiration: 0,
	}
	assert.True(t, x.Expired())

	x.Expiration = time.Now().UnixMilli()
	assert.True(t, x.Expired())

	// one minute buffer, in millisec
	x.Expiration = time.Now().UnixMilli() - 60*1000 + 1
	assert.True(t, x.Expired())

	x.Expiration = time.Now().UnixMilli() + 60*1000 + 1
	assert.False(t, x.Expired())
}

func TestRoleArn(t *testing.T) {
	x := &RoleCredentials{
		AccountId: 12344553243,
		RoleName:  "foobar",
	}
	assert.Equal(t, "arn:aws:iam::012344553243:role/foobar", x.RoleArn())
	assert.Equal(t, "012344553243", x.AccountIdStr())
}

func TestExpireEpoch(t *testing.T) {
	x := RoleCredentials{
		Expiration: 0,
	}
	assert.Equal(t, int64(0), x.ExpireEpoch())

	x.Expiration = time.Now().UnixMilli()
	assert.Equal(t, time.UnixMilli(x.Expiration).Unix(), x.ExpireEpoch())
}

func TestExpireString(t *testing.T) {
	x := RoleCredentials{
		Expiration: 0,
	}
	assert.Equal(t, time.Unix(0, 0).String(), x.ExpireString())

	x.Expiration = time.Now().UnixMilli()
	assert.Equal(t, time.UnixMilli(x.Expiration).String(), x.ExpireString())
}

func TestExpireISO8601(t *testing.T) {
	x := RoleCredentials{
		Expiration: 0,
	}
	assert.Equal(t, time.Unix(0, 0).Format(time.RFC3339), x.ExpireISO8601())

	x.Expiration = time.Now().Unix()
	assert.Equal(t, time.UnixMilli(x.Expiration).Format(time.RFC3339), x.ExpireISO8601())
}
