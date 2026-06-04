package storage

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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	testlogger "github.com/synfinatic/flexlog/test"
)

type KeyringSuite struct {
	suite.Suite
	store SecureStorage
}

func TestKeyringSuite(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	// need to set this here as we're not using the normal location during tests
	flockFile = path.Join(d, "storage.lock")

	defer func() {
		os.RemoveAll(d)
		os.Unsetenv(ENV_SSO_FILE_PASSWORD)
	}()

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d, "")
	assert.NoError(t, err)

	s := KeyringSuite{}
	s.store, err = OpenKeyring(context.Background(), c)
	assert.NoError(t, err)
	suite.Run(t, &s)
}

func (suite *KeyringSuite) TestRegisterClientData() {
	t := suite.T()

	rcd := RegisterClientData{
		AuthorizationEndpoint: "https://foobar.com",
		ClientId:              "ThisIsNotARealClientId",
		ClientIdIssuedAt:      time.Now().Unix(),
		ClientSecret:          "WeAllWishForGreatness",
		ClientSecretExpiresAt: time.Now().Unix() + 1,
		TokenEndpoint:         "IhavenoideawhatI'mdoing",
	}
	err := suite.store.SaveRegisterClientData(context.Background(), "foo", rcd)
	assert.NoError(t, err)

	rcd2 := RegisterClientData{}
	err = suite.store.GetRegisterClientData("foo", &rcd2)
	assert.NoError(t, err)
	assert.Equal(t, rcd, rcd2)

	err = suite.store.DeleteRegisterClientData(context.Background(), "foo")
	assert.NoError(t, err)

	err = suite.store.GetRegisterClientData("foo", &rcd2)
	assert.Error(t, err)

	err = suite.store.GetRegisterClientData("cow", &rcd2)
	assert.Error(t, err)

	err = suite.store.DeleteRegisterClientData(context.Background(), "cow")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestCreateTokenResponse() {
	t := suite.T()

	ctr := CreateTokenResponse{
		AccessToken:  "Foobar",
		ExpiresIn:    60,
		ExpiresAt:    time.Now().Unix() + 60,
		IdToken:      "hellothere",
		RefreshToken: "just another token",
		TokenType:    "yes",
	}
	err := suite.store.SaveCreateTokenResponse(context.Background(), "foo", ctr)
	assert.NoError(t, err)

	ctr2 := CreateTokenResponse{}
	err = suite.store.GetCreateTokenResponse("foo", &ctr2)
	assert.NoError(t, err)
	assert.Equal(t, ctr, ctr2)

	err = suite.store.DeleteCreateTokenResponse(context.Background(), "foo")
	assert.NoError(t, err)

	err = suite.store.GetCreateTokenResponse("cow", &ctr2)
	assert.Error(t, err)

	err = suite.store.DeleteCreateTokenResponse(context.Background(), "cow")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestRoleCredentials() {
	t := suite.T()

	rc := RoleCredentials{ // nolint:gosec
		RoleName:        "MyRole",
		AccountId:       234566767,
		AccessKeyId:     "some not-so-secret-string",
		SecretAccessKey: "a string we actually want to keep secret",
		SessionToken:    "Another secret string",
		Expiration:      time.Now().Unix(),
	}
	err := suite.store.SaveRoleCredentials(context.Background(), "foo", rc)
	assert.NoError(t, err)

	rc2 := RoleCredentials{}
	err = suite.store.GetRoleCredentials("foo", &rc2)
	assert.NoError(t, err)
	assert.Equal(t, rc, rc2)

	err = suite.store.DeleteRoleCredentials(context.Background(), "foo")
	assert.NoError(t, err)

	err = suite.store.GetRoleCredentials("foo", &rc2)
	assert.Error(t, err)

	err = suite.store.GetRoleCredentials("cow", &rc2)
	assert.Error(t, err)

	err = suite.store.DeleteRoleCredentials(context.Background(), "cow")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestEcsBearerToken() {
	t := suite.T()

	token, err := suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Empty(t, token)

	err = suite.store.SaveEcsBearerToken(context.Background(), "not a real token")
	assert.NoError(t, err)

	token, err = suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Equal(t, "not a real token", token)

	err = suite.store.DeleteEcsBearerToken(context.Background())
	assert.NoError(t, err)

	token, err = suite.store.GetEcsBearerToken()
	assert.NoError(t, err)
	assert.Empty(t, token)
}

func (suite *KeyringSuite) TestEcsSslKeyPair() { // nolint: dupl
	t := suite.T()

	cert, err := suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Empty(t, cert)

	key, err := suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Empty(t, key)

	certBytes, err := os.ReadFile("../ecs/server/testdata/localhost.crt")
	assert.NoError(t, err)
	keyBytes, err := os.ReadFile("../ecs/server/testdata/localhost.key")
	assert.NoError(t, err)

	err = suite.store.SaveEcsSslKeyPair(context.Background(), []byte{}, certBytes)
	assert.NoError(t, err)

	err = suite.store.SaveEcsSslKeyPair(context.Background(), keyBytes, certBytes)
	assert.NoError(t, err)

	err = suite.store.SaveEcsSslKeyPair(context.Background(), keyBytes, keyBytes)
	assert.Error(t, err)

	err = suite.store.SaveEcsSslKeyPair(context.Background(), certBytes, certBytes)
	assert.Error(t, err)

	cert, err = suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Equal(t, string(certBytes), cert)

	key, err = suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Equal(t, string(keyBytes), key)

	err = suite.store.DeleteEcsSslKeyPair(context.Background())
	assert.NoError(t, err)

	cert, err = suite.store.GetEcsSslCert()
	assert.NoError(t, err)
	assert.Empty(t, cert)

	key, err = suite.store.GetEcsSslKey()
	assert.NoError(t, err)
	assert.Empty(t, key)
}

func (suite *KeyringSuite) TestErrorReadKeyring() {
	t := suite.T()
	ks := suite.store.(*KeyringStore)
	// Read non existent key
	_, err := ks.joinAndGetKeyringData("XXXXX")
	assert.Error(t, err)
	// Read Wrong Data
	_ = ks.setStorageData([]byte{0}, "XXXXX_0", KEYRING_ID)
	_, err = ks.joinAndGetKeyringData("XXXXX")
	assert.Error(t, err)

	_ = ks.setStorageData([]byte{0, 0, 0, 0, 0, 0, 0, 1, 2, 3}, "XXXXX_0", KEYRING_ID)
	_, err = ks.joinAndGetKeyringData("XXXXX")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestJoinAndGetKeyringData() {
	t := suite.T()

	secretKey := "TestString"
	secretLabel := "TestLabel"
	dataLen := WINCRED_MAX_LENGTH*2 + 50
	secretData := make([]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		secretData[i] = 'A'
	}

	ks := suite.store.(*KeyringStore)

	err := ks.splitAndSetStorageData(secretData, secretKey, secretLabel)
	assert.NoError(t, err)

	ret, err := ks.joinAndGetKeyringData(secretKey)
	assert.NoError(t, err)
	assert.Equal(t, secretData, ret)
}

func TestGetStorageData(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	flockFile = path.Join(d, "storage.lock")
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d, "")
	assert.NoError(t, err)

	s := KeyringSuite{}
	s.store, err = OpenKeyring(context.Background(), c)
	assert.NoError(t, err)
	suite.Run(t, &s)
}

type mockKeyringAPI struct{}

func (m *mockKeyringAPI) Get(key string) (keyring.Item, error) {
	return keyring.Item{}, fmt.Errorf("Unable to get %s", key)
}

func (m *mockKeyringAPI) Set(item keyring.Item) error {
	return fmt.Errorf("Unable to set item")
}

func (m *mockKeyringAPI) Remove(key string) error {
	return fmt.Errorf("Unable to remove %s", key)
}

func TestKeyringErrors(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	flockFile = path.Join(d, "storage.lock")
	defer os.RemoveAll(d)

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d, "")
	assert.NoError(t, err)

	ks := &KeyringStore{
		keyring: &mockKeyringAPI{},
		config:  *c,
		cache:   NewStorageData(),
	}

	err = ks.getStorageData(context.Background(), &StorageData{})
	assert.NoError(t, err)

	err = ks.saveStorageData(context.Background())
	assert.Error(t, err)

	// RegisterClientData
	err = ks.GetRegisterClientData("region", &RegisterClientData{})
	assert.Error(t, err)

	err = ks.SaveRegisterClientData(context.Background(), "region", RegisterClientData{})
	assert.Error(t, err)

	err = ks.DeleteRegisterClientData(context.Background(), "region")
	assert.Error(t, err)

	// RoleCredentials
	err = ks.GetRoleCredentials("foo", &RoleCredentials{})
	assert.Error(t, err)

	err = ks.SaveRoleCredentials(context.Background(), "foo", RoleCredentials{})
	assert.Error(t, err)

	err = ks.DeleteRoleCredentials(context.Background(), "bar")
	assert.Error(t, err)

	// CreateTokenResponse
	err = ks.GetCreateTokenResponse("key", &CreateTokenResponse{})
	assert.Error(t, err)

	err = ks.SaveCreateTokenResponse(context.Background(), "key", CreateTokenResponse{})
	assert.Error(t, err)

	err = ks.DeleteCreateTokenResponse(context.Background(), "key")
	assert.Error(t, err)
}

func (suite *KeyringSuite) TestCreateKeys() {
	t := suite.T()

	ks := suite.store.(*KeyringStore)
	assert.Equal(t, "token-response:mykey", ks.CreateTokenResponseKey("mykey"))
	assert.Equal(t, "client-data:mykey", ks.RegisterClientKey("mykey"))
}

func (suite *KeyringSuite) TestStaticCredentials() { //nolint:dupl
	t := suite.T()

	arn := "arn:aws:iam::123456789012:role/foobar"
	cr := StaticCredentials{ // nolint:gosec
		UserName:        "foobar",
		AccountId:       123456789012,
		AccessKeyId:     "not a real access key id",
		SecretAccessKey: "not a real access key",
	}
	assert.Empty(t, suite.store.ListStaticCredentials())

	assert.NoError(t, suite.store.SaveStaticCredentials(context.Background(), arn, cr))
	assert.Equal(t, []string{arn}, suite.store.ListStaticCredentials())

	cr2 := StaticCredentials{}
	assert.NoError(t, suite.store.GetStaticCredentials(arn, &cr2))
	assert.Equal(t, cr, cr2)

	assert.NoError(t, suite.store.DeleteStaticCredentials(context.Background(), arn))
	assert.Empty(t, suite.store.ListStaticCredentials())
	assert.Error(t, suite.store.GetStaticCredentials(arn, &cr2))
	assert.Error(t, suite.store.DeleteStaticCredentials(context.Background(), arn))
}

func TestNewStorageData(t *testing.T) {
	s := NewStorageData()
	assert.Empty(t, s.RegisterClientData)
	assert.Empty(t, s.CreateTokenResponse)
	assert.Empty(t, s.RoleCredentials)
}

func TestFileKeyringPassword(t *testing.T) {
	defer func() {
		os.Setenv(ENV_SSO_FILE_PASSWORD, "")
		NewPassword = ""
	}()

	os.Setenv(ENV_SSO_FILE_PASSWORD, "foobar")
	p, err := fileKeyringPassword("prompt")
	assert.NoError(t, err)
	assert.Equal(t, "foobar", p)

	os.Unsetenv(ENV_SSO_FILE_PASSWORD)
	NewPassword = "foobar2"
	p, err = fileKeyringPassword("prompt")
	assert.NoError(t, err)
	assert.Equal(t, "foobar2", p)
}

func getPasswordErrorFunc(p string) (string, error) {
	return "", fmt.Errorf("error")
}

var getPasswords []string = []string{"first", "second", "unused"}

func getPasswordDifferentFunc(p string) (string, error) {
	var x string
	x, getPasswords = getPasswords[0], getPasswords[1:]
	return x, nil
}

var getPasswordErrorDifferentFuncCount int = 0

func getPasswordErrorDifferentFunc(p string) (string, error) {
	if getPasswordErrorDifferentFuncCount == 0 {
		getPasswordErrorDifferentFuncCount += 1
		return "foo", nil
	} else {
		return "", fmt.Errorf("error")
	}
}

func TestNewKeyringConfig(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	flockFile = path.Join(d, "storage.lock")

	defer func() {
		getPasswordFunc = fileKeyringPassword
		os.RemoveAll(d)
	}()

	err = os.WriteFile(path.Join(d, "aws-sso-cli-records"), []byte("INVALID DATA"), 0600)
	assert.NoError(t, err)

	getPasswordFunc = getPasswordErrorFunc
	_, err = NewKeyringConfig("file", d, "")
	assert.Error(t, err)

	getPasswordFunc = getPasswordDifferentFunc
	_, err = NewKeyringConfig("file", d, "")
	assert.Error(t, err)

	getPasswordFunc = getPasswordErrorDifferentFunc
	_, err = NewKeyringConfig("file", d, "")
	assert.Error(t, err)

	getPasswordFunc = getPasswordDifferentFunc
	getPasswords = []string{"password", "password"}
	_, err = NewKeyringConfig("file", d, "")
	assert.NoError(t, err)
	assert.Equal(t, "password", NewPassword)
}

func TestNewKeyringConfigCollectionName(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring-collection")
	assert.NoError(t, err)
	defer os.RemoveAll(d)

	// empty collectionName falls back to KEYRING_NAME
	c, err := NewKeyringConfig("", d, "")
	assert.NoError(t, err)
	assert.Equal(t, KEYRING_NAME, c.LibSecretCollectionName)

	// non-empty collectionName is propagated
	c, err = NewKeyringConfig("", d, "mycollection")
	assert.NoError(t, err)
	assert.Equal(t, "mycollection", c.LibSecretCollectionName)
}

func TestKeyringSuiteFails(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	flockFile = path.Join(d, "storage.lock")
	err = os.MkdirAll(path.Join(d, "secure"), 0755)
	assert.NoError(t, err)

	defer func() {
		os.RemoveAll(d)
		os.Unsetenv(ENV_SSO_FILE_PASSWORD)
		storageDataUnmarshal = json.Unmarshal
	}()

	os.Setenv(ENV_SSO_FILE_PASSWORD, "happy1")
	c, err := NewKeyringConfig("file", d, "")
	assert.NoError(t, err)

	ring, err := keyring.Open(*c)
	assert.NoError(t, err)

	kr := &KeyringStore{
		keyring: ring,
		cache:   NewStorageData(),
	}
	storageDataUnmarshal = func(s []byte, i interface{}) error {
		return fmt.Errorf("unmarshal failure")
	}

	in, err := os.ReadFile("./testdata/aws-sso-cli-records")
	assert.NoError(t, err)

	err = os.WriteFile(path.Join(d, "secure", "aws-sso-cli-records"), in, 0600)
	assert.NoError(t, err)

	err = kr.getStorageData(context.Background(), &kr.cache)
	assert.Error(t, err)
	assert.Equal(t, "unmarshal failure", err.Error())

	_, err = OpenKeyring(context.Background(), c)
	assert.Error(t, err)
	assert.Equal(t, "unmarshal failure", err.Error())
}

func TestSplitCredentials(t *testing.T) {
	d, err := os.MkdirTemp("", "test-keyring")
	assert.NoError(t, err)
	flockFile = path.Join(d, "storage.lock")

	// setup logger for testing
	oldLogger := log.Copy()
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()

	log = tLogger
	defer func() { log = oldLogger }()

	defer func() {
		os.RemoveAll(d)
		os.Unsetenv(ENV_SSO_FILE_PASSWORD)
		keyringGOOS = ""
	}()

	os.Setenv(ENV_SSO_FILE_PASSWORD, "justapassword")
	c, err := NewKeyringConfig("file", d, "")
	assert.NoError(t, err)

	store, err := OpenKeyring(context.Background(), c)
	assert.NoError(t, err)

	rc := RoleCredentials{ // nolint:gosec
		RoleName:        "MyRole",
		AccountId:       234566767,
		AccessKeyId:     "some not-so-secret-string",
		SecretAccessKey: "a string we actually want to keep secret",
		SessionToken:    "Another secret string",
		Expiration:      time.Now().Unix(),
	}

	x := make([]string, 50)
	for i := 0; i < 50; i++ {
		x = append(x, `Lorem ipsum dolor sit amet, consectetur adipiscing elit.
		Integer sollicitudin ligula ac lectus lobortis, sit amet laoreet lacus finibus.`)
	}
	largeString := strings.Join(x, " ")

	largeRC := RoleCredentials{
		RoleName:        "MyRole",
		AccountId:       234566767,
		AccessKeyId:     "some not-so-secret-string",
		SecretAccessKey: largeString,
		SessionToken:    "Another secret string",
		Expiration:      time.Now().Unix(),
	}

	keyringGOOS = "linux"
	err = store.SaveRoleCredentials(context.Background(), "bar", largeRC)
	assert.NoError(t, err)
	rc2 := RoleCredentials{}
	err = store.GetRoleCredentials("bar", &rc2)
	assert.NoError(t, err)
	assert.Equal(t, largeRC, rc2)
	err = store.DeleteRoleCredentials(context.Background(), "bar")
	assert.NoError(t, err)

	keyringGOOS = "windows"
	err = store.SaveRoleCredentials(context.Background(), "bar", largeRC)
	assert.NoError(t, err)
	rc2 = RoleCredentials{}
	err = store.GetRoleCredentials("bar", &rc2)
	assert.NoError(t, err)
	assert.Equal(t, largeRC, rc2)
	err = store.DeleteRoleCredentials(context.Background(), "bar")
	assert.NoError(t, err)
	err = store.SaveRoleCredentials(context.Background(), "bar", rc)
	assert.NoError(t, err)
	rc2 = RoleCredentials{}

	err = store.GetRoleCredentials("bar", &rc2)
	assert.NoError(t, err)
	assert.Equal(t, rc, rc2)
	err = store.DeleteRoleCredentials(context.Background(), "bar")
	assert.NoError(t, err)

	// Replace a chunk with wrong data
	err = store.SaveRoleCredentials(context.Background(), "bar", largeRC)
	assert.NoError(t, err)

	ks := store.(*KeyringStore)

	err = ks.setStorageData([]byte("hello friend"), fmt.Sprintf("%s_%d", RECORD_KEY, 1), KEYRING_ID)
	assert.NoError(t, err)
	_, err = ks.joinAndGetKeyringData(RECORD_KEY)
	assert.Error(t, err)

	// but OpenKeyring is fine
	_, err = OpenKeyring(context.Background(), c)
	assert.NoError(t, err)
}
