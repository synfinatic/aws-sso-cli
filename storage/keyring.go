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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/99designs/keyring"
	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	KEYRING_ID                   = "aws-sso-cli"
	RECORD_KEY                   = "aws-sso-cli-records"
	KEYRING_NAME                 = "awsssocli"
	REGISTER_CLIENT_DATA_PREFIX  = "client-data"
	CREATE_TOKEN_RESPONSE_PREFIX = "token-response"
	ENV_SSO_FILE_PASSWORD        = "AWS_SSO_FILE_PASSWORD" // #nosec
	WINCRED_MAX_LENGTH           = 2000
)

// Implements SecureStorage
type KeyringStore struct {
	keyring KeyringAPI
	config  keyring.Config
	cache   StorageData
}

type StorageData struct {
	RegisterClientData  map[string]RegisterClientData
	CreateTokenResponse map[string]CreateTokenResponse
	RoleCredentials     map[string]RoleCredentials
	StaticCredentials   map[string]StaticCredentials
}

func NewStorageData() StorageData {
	return StorageData{
		RegisterClientData:  map[string]RegisterClientData{},
		CreateTokenResponse: map[string]CreateTokenResponse{},
		RoleCredentials:     map[string]RoleCredentials{},
		StaticCredentials:   map[string]StaticCredentials{},
	}
}

var NewPassword string = ""
var keyringGOOS string = runtime.GOOS

// KeyringAPI is the subset of the Keyring API we use so we can do unit testing
type KeyringAPI interface {
	// Returns an Item matching the key or ErrKeyNotFound
	Get(key string) (keyring.Item, error)
	// Returns the non-secret parts of an Item
	// GetMetadata(key string) (Metadata, error)
	// Stores an Item on the keyring
	Set(item keyring.Item) error
	// Removes the item with matching key
	Remove(key string) error
	// Provides a slice of all keys stored on the keyring
	// Keys() ([]string, error)
}

type getPassword func(string) (string, error)

var getPasswordFunc getPassword = fileKeyringPassword

func NewKeyringConfig(name, configDir string) (*keyring.Config, error) {
	securePath := path.Join(configDir, "secure")

	c := keyring.Config{
		ServiceName: KEYRING_ID, // generic backend provider
		// macOS KeyChain
		KeychainTrustApplication:       true,  // stop asking user for passwords
		KeychainSynchronizable:         false, // no iCloud sync
		KeychainAccessibleWhenUnlocked: false, // no reads while device locked
		// KeychainPasswordFunc: ???,
		// Other systems below this line
		FileDir:                 securePath,
		FilePasswordFunc:        fileKeyringPassword,
		LibSecretCollectionName: KEYRING_NAME,
		KWalletAppID:            KEYRING_ID,
		KWalletFolder:           KEYRING_ID,
		WinCredPrefix:           KEYRING_ID,
	}
	if name != "" {
		c.AllowedBackends = []keyring.BackendType{keyring.BackendType(name)}
		rolesFile := utils.GetHomePath(path.Join(securePath, RECORD_KEY))

		if name == "file" {
			if _, err := os.Stat(rolesFile); os.IsNotExist(err) {
				// new secure store, so we should prompt user twice for password
				// if ENV var is not set
				if password := os.Getenv(ENV_SSO_FILE_PASSWORD); password == "" {
					pass1, err := getPasswordFunc("Select password")
					if err != nil {
						return &c, fmt.Errorf("Password error: %s", err.Error())
					}
					pass2, err := getPasswordFunc("Verify password")
					if err != nil {
						return &c, fmt.Errorf("Password error: %s", err.Error())
					}
					if pass1 != pass2 {
						return &c, fmt.Errorf("Password missmatch")
					}
					NewPassword = pass1
				}
			}
		}
	}
	return &c, nil
}

func fileKeyringPassword(prompt string) (string, error) {
	if password := os.Getenv(ENV_SSO_FILE_PASSWORD); password != "" {
		return password, nil
	}
	if NewPassword != "" {
		return NewPassword, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	s := string(b)
	if s == "" {
		fmt.Println()
		log.Fatalf("Aborting with empty password")
	}
	fmt.Println()
	return s, nil
}

func OpenKeyring(cfg *keyring.Config) (*KeyringStore, error) {
	ring, err := keyring.Open(*cfg)
	if err != nil {
		return nil, err
	}
	kr := KeyringStore{
		keyring: ring,
		config:  *cfg,
		cache:   NewStorageData(),
	}

	if err = kr.getStorageData(&kr.cache); err != nil {
		return nil, err
	}

	return &kr, nil
}

func (kr *KeyringStore) RegisterClientKey(ssoRegion string) string {
	return fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, ssoRegion)
}

type Unmarshaler func([]byte, interface{}) error

var storageDataUnmarshal Unmarshaler = json.Unmarshal

// loads the entire StorageData into memory
func (kr *KeyringStore) getStorageData(s *StorageData) error {
	var data []byte
	var err error

	switch keyringGOOS {
	case "windows":
		data, err = kr.joinAndGetKeyringData(RECORD_KEY)
	default:
		data, err = kr.getKeyringData(RECORD_KEY)
	}

	if err != nil {
		log.Warn(err)
		// Didn't find anything in our keyring
		*s = NewStorageData()
		return nil
	}

	if err = storageDataUnmarshal(data, s); err != nil {
		return err
	}
	return nil
}

// reads a single entry of the keyring
func (kr *KeyringStore) getKeyringData(key string) ([]byte, error) {
	data, err := kr.keyring.Get(key)
	if err != nil {
		return nil, err
	}
	return data.Data, nil
}

// read the chunks stored in windows credential manager
func (kr *KeyringStore) joinAndGetKeyringData(key string) ([]byte, error) {
	var err error
	var chunk []byte

	if chunk, err = kr.getKeyringData(fmt.Sprintf("%s_%d", key, 0)); err != nil {
		return nil, err
	}

	if len(chunk) < 8 {
		return nil, fmt.Errorf("Invalid stored data in Keyring. Only %d bytes", len(chunk))
	}

	totalBytes, data := binary.BigEndian.Uint64(chunk[:8]), chunk[8:]
	readBytes := uint64(len(chunk))

	for i := 1; readBytes < totalBytes; i++ {
		k := fmt.Sprintf("%s_%d", key, i)
		if chunk, err = kr.getKeyringData(k); err != nil {
			return nil, fmt.Errorf("Unable to fetch %s: %s", k, err.Error())
		}
		data = append(data, chunk...)
		readBytes += uint64(len(chunk))
	}

	if readBytes != totalBytes {
		return nil, fmt.Errorf("Invalid stored data in Keyring.  Expected %d bytes, but read %d bytes of data",
			totalBytes, readBytes)
	}
	return data, nil
}

// saves the entire StorageData into our KeyringStore
func (kr *KeyringStore) saveStorageData() error {
	var err error
	jdata, _ := json.Marshal(kr.cache)

	switch keyringGOOS {
	case "windows":
		err = kr.splitAndSetStorageData(jdata, RECORD_KEY, KEYRING_ID)
	default:
		err = kr.setStorageData(jdata, RECORD_KEY, KEYRING_ID)
	}
	return err
}

// splitAndSetStorageData writes all the data in WINCRED_MAX_LENGTH length chunks
func (kr *KeyringStore) splitAndSetStorageData(jdata []byte, key string, label string) error {
	var i int
	remain := jdata
	var chunk []byte
	payloadSize := make([]byte, 8)
	binary.BigEndian.PutUint64(payloadSize, uint64(len(jdata)))

	for i = 0; len(remain) >= WINCRED_MAX_LENGTH; i++ {
		chunk, remain = remain[:WINCRED_MAX_LENGTH], remain[WINCRED_MAX_LENGTH:]
		if i == 0 {
			chunk = append(payloadSize, chunk...)
		}
		if err := kr.setStorageData(chunk, fmt.Sprintf("%s_%d", key, i), label); err != nil {
			return err
		}
	}

	if len(remain) > 0 {
		if i == 0 {
			remain = append(payloadSize, remain...)
		}
		err := kr.setStorageData(remain, fmt.Sprintf("%s_%d", key, i), label)
		if err != nil {
			return err
		}
	}

	return nil
}

// setStorageData writes all the data as a single entry
func (kr *KeyringStore) setStorageData(jdata []byte, key string, label string) error {
	err := kr.keyring.Set(keyring.Item{
		Key:         key,
		Data:        jdata,
		Label:       label,
		Description: "aws-sso secure storage",
	})

	return err
}

// Save our RegisterClientData in the key chain
func (kr *KeyringStore) SaveRegisterClientData(region string, client RegisterClientData) error {
	key := kr.RegisterClientKey(region)
	kr.cache.RegisterClientData[key] = client

	return kr.saveStorageData()
}

// Get our RegisterClientData from the key chain
func (kr *KeyringStore) GetRegisterClientData(region string, client *RegisterClientData) error {
	var ok bool
	key := kr.RegisterClientKey(region)
	if *client, ok = kr.cache.RegisterClientData[key]; !ok {
		return fmt.Errorf("No RegisterClientData for %s", region)
	}
	return nil
}

// Delete the RegisterClientData from the keychain
func (kr *KeyringStore) DeleteRegisterClientData(region string) error {
	key := kr.RegisterClientKey(region)
	if _, ok := kr.cache.RegisterClientData[key]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("No RegisterClientData for key: %s", key)
	}

	delete(kr.cache.RegisterClientData, key)
	return kr.saveStorageData()
}

func (kr *KeyringStore) CreateTokenResponseKey(key string) string {
	return fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
}

// SaveCreateTokenResponse stores the token in the keyring
func (kr *KeyringStore) SaveCreateTokenResponse(key string, token CreateTokenResponse) error {
	k := kr.CreateTokenResponseKey(key)
	kr.cache.CreateTokenResponse[k] = token

	return kr.saveStorageData()
}

// GetCreateTokenResponse retrieves the CreateTokenResponse from the keyring
func (kr *KeyringStore) GetCreateTokenResponse(key string, token *CreateTokenResponse) error {
	var ok bool
	k := kr.CreateTokenResponseKey(key)
	if *token, ok = kr.cache.CreateTokenResponse[k]; !ok {
		return fmt.Errorf("No CreateTokenResponse for %s", k)
	}
	return nil
}

// DeleteCreateTokenResponse deletes the CreateTokenResponse from the keyring
func (kr *KeyringStore) DeleteCreateTokenResponse(key string) error {
	k := kr.CreateTokenResponseKey(key)
	if _, ok := kr.cache.CreateTokenResponse[k]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("No CreateTokenResponse for key: %s", k)
	}

	delete(kr.cache.CreateTokenResponse, k)
	return kr.saveStorageData()
}

// SaveRoleCredentials stores the token in the arnring
func (kr *KeyringStore) SaveRoleCredentials(arn string, token RoleCredentials) error {
	kr.cache.RoleCredentials[arn] = token
	return kr.saveStorageData()
}

// GetRoleCredentials retrieves the RoleCredentials from the Keyring
func (kr *KeyringStore) GetRoleCredentials(arn string, token *RoleCredentials) error {
	var ok bool
	if *token, ok = kr.cache.RoleCredentials[arn]; !ok {
		return fmt.Errorf("No RoleCredentials for ARN: %s", arn)
	}
	return nil
}

// DeleteRoleCredentials deletes the RoleCredentials from the Keyring
func (kr *KeyringStore) DeleteRoleCredentials(arn string) error {
	if _, ok := kr.cache.RoleCredentials[arn]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("No RoleCredentials for ARN: %s", arn)
	}

	delete(kr.cache.RoleCredentials, arn)
	return kr.saveStorageData()
}

// SaveStaticCredentials stores the token in the arnring
func (kr *KeyringStore) SaveStaticCredentials(arn string, creds StaticCredentials) error {
	kr.cache.StaticCredentials[arn] = creds
	return kr.saveStorageData()
}

// GetStaticCredentials retrieves the StaticCredentials from the Keyring
func (kr *KeyringStore) GetStaticCredentials(arn string, creds *StaticCredentials) error {
	var ok bool
	if *creds, ok = kr.cache.StaticCredentials[arn]; !ok {
		return fmt.Errorf("No StaticCredentials for ARN: %s", arn)
	}
	return nil
}

// DeleteStaticCredentials deletes the StaticCredentials from the Keyring
func (kr *KeyringStore) DeleteStaticCredentials(arn string) error {
	if _, ok := kr.cache.StaticCredentials[arn]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("No StaticCredentials for ARN: %s", arn)
	}

	delete(kr.cache.StaticCredentials, arn)
	return kr.saveStorageData()
}

func (kr *KeyringStore) ListStaticCredentials() []string {
	ret := make([]string, len(kr.cache.StaticCredentials))
	i := 0
	for k := range kr.cache.StaticCredentials {
		ret[i] = k
		i++
	}
	return ret
}
