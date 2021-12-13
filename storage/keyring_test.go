package storage

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestKeyring(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d)
	assert.NoError(t, err)

	s, err := OpenKeyring(c)
	assert.NoError(t, err)

	data := NewStorageData()
	rcd := RegisterClientData{
		AuthorizationEndpoint: "https://foobar.com",
		ClientId:              "ThisIsNotARealClientId",
		ClientIdIssuedAt:      time.Now().Unix(),
		ClientSecret:          "WeAllWishForGreatness",
		ClientSecretExpiresAt: time.Now().Unix() + 1,
		TokenEndpoint:         "IhavenoideawhatI'mdoing",
	}
	data.RegisterClientData["foo"] = rcd

	err = s.saveStorageData(data)
	assert.NoError(t, err)

	data2 := NewStorageData()
	err = s.getStorageData(&data2)
	assert.NoError(t, err)
	assert.Equal(t, data, data2)

	err = s.SaveRegisterClientData("bar", rcd)
	assert.NoError(t, err)
	rcd2 := RegisterClientData{}

	err = s.GetRegisterClientData("bar", &rcd2)
	assert.NoError(t, err)
	assert.Equal(t, rcd, rcd2)

	err = s.GetRegisterClientData("cow", &rcd2)
	assert.Error(t, err)
}
