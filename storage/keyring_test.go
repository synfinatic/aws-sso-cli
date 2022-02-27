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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type KeyringSuite struct {
	suite.Suite
	store *KeyringStore
}

func TestKeyringSuite(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d)
	assert.NoError(t, err)

	s := KeyringSuite{}
	s.store, err = OpenKeyring(c)
	assert.NoError(t, err)
	suite.Run(t, &s)
}

func TestKeyringSuiteFails(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	in, err := ioutil.ReadFile("./testdata/bad_store.json")
	assert.NoError(t, err)

	err = ioutil.WriteFile(path.Join(d, "store.json"), in, 0600)
	assert.NoError(t, err)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("json", d)
	assert.NoError(t, err)

	s := KeyringSuite{}
	s.store, err = OpenKeyring(c)
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestRegisterClientData() {
	t := suite.T()

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

	err := suite.store.saveStorageData(data)
	assert.NoError(t, err)

	data2 := NewStorageData()
	err = suite.store.getStorageData(&data2)
	assert.NoError(t, err)
	assert.Equal(t, data, data2)

	err = suite.store.SaveRegisterClientData("bar", rcd)
	assert.NoError(t, err)

	rcd2 := RegisterClientData{}
	err = suite.store.GetRegisterClientData("bar", &rcd2)
	assert.NoError(t, err)
	assert.Equal(t, rcd, rcd2)

	err = suite.store.GetRegisterClientData("cow", &rcd2)
	assert.Error(t, err)

	err = suite.store.DeleteRegisterClientData("bar")
	assert.NoError(t, err)

	err = suite.store.DeleteCreateTokenResponse("what")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestCreateTokenResponse() {
	t := suite.T()

	data := NewStorageData()
	ctr := CreateTokenResponse{
		AccessToken:  "Foobar",
		ExpiresIn:    60,
		ExpiresAt:    time.Now().Unix() + 60,
		IdToken:      "hellothere",
		RefreshToken: "just another token",
		TokenType:    "yes",
	}
	data.CreateTokenResponse["foo"] = ctr
	err := suite.store.saveStorageData(data)
	assert.NoError(t, err)

	data2 := NewStorageData()
	err = suite.store.getStorageData(&data2)
	assert.NoError(t, err)
	assert.Equal(t, data, data2)

	err = suite.store.SaveCreateTokenResponse("bar", ctr)
	assert.NoError(t, err)

	ctr2 := CreateTokenResponse{}
	err = suite.store.GetCreateTokenResponse("bar", &ctr2)
	assert.NoError(t, err)
	assert.Equal(t, ctr, ctr2)

	err = suite.store.GetCreateTokenResponse("cow", &ctr2)
	assert.Error(t, err)

	err = suite.store.DeleteCreateTokenResponse("bar")
	assert.NoError(t, err)

	err = suite.store.DeleteRoleCredentials("what")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestRoleCredentials() {
	t := suite.T()

	data := NewStorageData()
	rc := RoleCredentials{
		RoleName:        "MyRole",
		AccountId:       234566767,
		AccessKeyId:     "some not-so-secret-string",
		SecretAccessKey: "a string we actually want to keep secret",
		SessionToken:    "Another secret string",
		Expiration:      time.Now().Unix(),
	}
	data.RoleCredentials["foo"] = rc
	err := suite.store.saveStorageData(data)
	assert.NoError(t, err)

	data2 := NewStorageData()
	err = suite.store.getStorageData(&data2)
	assert.NoError(t, err)
	assert.Equal(t, data, data2)

	err = suite.store.SaveRoleCredentials("bar", rc)
	assert.NoError(t, err)

	rc2 := RoleCredentials{}
	err = suite.store.GetRoleCredentials("bar", &rc2)
	assert.NoError(t, err)
	assert.Equal(t, rc, rc2)

	err = suite.store.GetRoleCredentials("cow", &rc2)
	assert.Error(t, err)

	err = suite.store.DeleteRoleCredentials("bar")
	assert.NoError(t, err)

	err = suite.store.DeleteRoleCredentials("what")
	assert.Error(t, err)
}

func TestGetStorageData(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d)
	assert.NoError(t, err)

	s := KeyringSuite{}
	s.store, err = OpenKeyring(c)
	assert.NoError(t, err)
	suite.Run(t, &s)
}

type mockKeyringApi struct{}

func (m *mockKeyringApi) Get(key string) (keyring.Item, error) {
	return keyring.Item{}, fmt.Errorf("Unable to get %s", key)
}

func (m *mockKeyringApi) Set(item keyring.Item) error {
	return fmt.Errorf("Unable to set item")
}

func (m *mockKeyringApi) Remove(key string) error {
	return fmt.Errorf("Unable to remove %s", key)
}

func TestKeyringErrors(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d)
	assert.NoError(t, err)

	ks := &KeyringStore{
		keyring: &mockKeyringApi{},
		config:  *c,
	}

	err = ks.getStorageData(&StorageData{})
	assert.NoError(t, err)

	err = ks.saveStorageData(StorageData{})
	assert.Error(t, err)

	// RegisterClientData
	err = ks.GetRegisterClientData("region", &RegisterClientData{})
	assert.Error(t, err)

	err = ks.SaveRegisterClientData("region", RegisterClientData{})
	assert.Error(t, err)

	err = ks.DeleteRegisterClientData("region")
	assert.Error(t, err)

	// RoleCredentials
	err = ks.GetRoleCredentials("foo", &RoleCredentials{})
	assert.Error(t, err)

	err = ks.SaveRoleCredentials("foo", RoleCredentials{})
	assert.Error(t, err)

	err = ks.DeleteRoleCredentials("bar")
	assert.Error(t, err)

	// CreateTokenResponse
	err = ks.GetCreateTokenResponse("key", &CreateTokenResponse{})
	assert.Error(t, err)

	err = ks.SaveCreateTokenResponse("key", CreateTokenResponse{})
	assert.Error(t, err)

	err = ks.DeleteCreateTokenResponse("key")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestCreateKeys() {
	t := suite.T()

	assert.Equal(t, "token-response:mykey", suite.store.CreateTokenResponseKey("mykey"))
	assert.Equal(t, "client-data:mykey", suite.store.RegisterClientKey("mykey"))
}

func UnmarshalFailure(s []byte, i interface{}) error {
	return fmt.Errorf("unmarshal failure")
}

func (suite *KeyringSuite) TestUnmarshalFailure() {
	t := suite.T()

	storageDataUnmarshal = UnmarshalFailure

	err := suite.store.SaveRegisterClientData("region", RegisterClientData{})
	assert.Error(t, err)

	err = suite.store.GetRegisterClientData("region", &RegisterClientData{})
	assert.Error(t, err)

	err = suite.store.DeleteRegisterClientData("region")
	assert.Error(t, err)

	err = suite.store.SaveCreateTokenResponse("key", CreateTokenResponse{})
	assert.Error(t, err)

	err = suite.store.GetCreateTokenResponse("key", &CreateTokenResponse{})
	assert.Error(t, err)

	err = suite.store.DeleteCreateTokenResponse("key")
	assert.Error(t, err)

	err = suite.store.SaveRoleCredentials("arn", RoleCredentials{})
	assert.Error(t, err)

	err = suite.store.GetRoleCredentials("arn", &RoleCredentials{})
	assert.Error(t, err)

	err = suite.store.DeleteRoleCredentials("arn")
	assert.Error(t, err)

	storageDataUnmarshal = json.Unmarshal
}
