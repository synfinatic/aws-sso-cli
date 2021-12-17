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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	KEYRING_ID                   = "aws-sso-cli"
	RECORD_KEY                   = "aws-sso-cli-records"
	KEYRING_NAME                 = "awsssocli"
	REGISTER_CLIENT_DATA_PREFIX  = "client-data"
	CREATE_TOKEN_RESPONSE_PREFIX = "token-response"
	ENV_SSO_FILE_PASSWORD        = "AWS_SSO_FILE_PASSWORD" // #nosec
)

// Implements SecureStorage
type KeyringStore struct {
	keyring keyring.Keyring
	config  keyring.Config
}

var NewPassword string = ""

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
		rolesFile := getHomePath(path.Join(securePath, RECORD_KEY))

		if name == "file" {
			if _, err := os.Stat(rolesFile); os.IsNotExist(err) {
				// new secure store, so we should prompt user twice for password
				// if ENV var is not set
				if password := os.Getenv(ENV_SSO_FILE_PASSWORD); password == "" {
					pass1, err := fileKeyringPassword("Select password")
					if err != nil {
						return &c, fmt.Errorf("Password error: %s", err.Error())
					}
					pass2, err := fileKeyringPassword("Verify password")
					if err != nil {
						return &c, fmt.Errorf("Password error: %s", err.Error())
					}
					if pass1 != pass2 {
						return &c, fmt.Errorf("Password missmatch: %s", err.Error())
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
	}
	return &kr, nil
}

func (kr *KeyringStore) RegisterClientKey(ssoRegion string) string {
	return fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, ssoRegion)
}

type StorageData struct {
	RegisterClientData  map[string]RegisterClientData
	CreateTokenResponse map[string]CreateTokenResponse
	RoleCredentials     map[string]RoleCredentials
}

func NewStorageData() StorageData {
	return StorageData{
		RegisterClientData:  map[string]RegisterClientData{},
		CreateTokenResponse: map[string]CreateTokenResponse{},
		RoleCredentials:     map[string]RoleCredentials{},
	}
}

// loads the entire StorageData into memory
func (kr *KeyringStore) getStorageData(s *StorageData) error {
	data, err := kr.keyring.Get(RECORD_KEY)
	if err != nil {
		// Didn't find anything in our keyring
		*s = NewStorageData()
		return nil
	}
	if err = json.Unmarshal(data.Data, s); err != nil {
		return err
	}
	return nil
}

// saves the entire StorageData into our KeyringStore
func (kr *KeyringStore) saveStorageData(s StorageData) error {
	jdata, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = kr.keyring.Set(keyring.Item{
		Key:         RECORD_KEY,
		Data:        jdata,
		Label:       KEYRING_ID,
		Description: "aws-sso secure storage",
	})

	// Work around bogus errors wincred storage issue.  Sadly doesn't seem
	// like we can tell if are using windcred, so just key off of the OS
	// https://github.com/99designs/keyring/issues/99
	if runtime.GOOS == "windows" && err.Error() == "The stub received bad data." {
		return nil
	}
	return err
}

// Save our RegisterClientData in the key chain
func (kr *KeyringStore) SaveRegisterClientData(region string, client RegisterClientData) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	key := kr.RegisterClientKey(region)
	storage.RegisterClientData[key] = client

	return kr.saveStorageData(storage)
}

// Get our RegisterClientData from the key chain
func (kr *KeyringStore) GetRegisterClientData(region string, client *RegisterClientData) error {
	storage := StorageData{}
	ok := false
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	key := kr.RegisterClientKey(region)
	if *client, ok = storage.RegisterClientData[key]; !ok {
		return fmt.Errorf("No RegisterClientData for %s", region)
	}
	return nil
}

// Delete the RegisterClientData from the keychain
func (kr *KeyringStore) DeleteRegisterClientData(region string) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	key := kr.RegisterClientKey(region)
	if _, ok := storage.RegisterClientData[key]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("Missing RegisterClientData for region: %s", region)
	}

	delete(storage.RegisterClientData, key)
	return nil
}

func (kr *KeyringStore) CreateTokenResponseKey(key string) string {
	return fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
}

// SaveCreateTokenResponse stores the token in the keyring
func (kr *KeyringStore) SaveCreateTokenResponse(key string, token CreateTokenResponse) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	k := kr.CreateTokenResponseKey(key)
	storage.CreateTokenResponse[k] = token

	return kr.saveStorageData(storage)
}

// GetCreateTokenResponse retrieves the CreateTokenResponse from the keyring
func (kr *KeyringStore) GetCreateTokenResponse(key string, token *CreateTokenResponse) error {
	storage := StorageData{}
	ok := false
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	k := kr.CreateTokenResponseKey(key)
	if *token, ok = storage.CreateTokenResponse[k]; !ok {
		return fmt.Errorf("No CreateTokenResponse for %s", key)
	}
	return nil
}

// DeleteCreateTokenResponse deletes the CreateTokenResponse from the keyring
func (kr *KeyringStore) DeleteCreateTokenResponse(key string) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	k := kr.CreateTokenResponseKey(key)
	if _, ok := storage.CreateTokenResponse[k]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("Missing CreateTokenResponse for key: %s", key)
	}

	delete(storage.CreateTokenResponse, k)
	return nil
}

// SaveRoleCredentials stores the token in the arnring
func (kr *KeyringStore) SaveRoleCredentials(arn string, token RoleCredentials) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return fmt.Errorf("Unable to getStorageData: %s", err.Error())
	}

	storage.RoleCredentials[arn] = token

	return kr.saveStorageData(storage)
}

// GetRoleCredentials retrieves the RoleCredentials from the Keyring
func (kr *KeyringStore) GetRoleCredentials(arn string, token *RoleCredentials) error {
	storage := StorageData{}
	ok := false
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	if *token, ok = storage.RoleCredentials[arn]; !ok {
		return fmt.Errorf("No RoleCredentials for %s", arn)
	}
	return nil
}

// DeleteRoleCredentials deletes the RoleCredentials from the Keyring
func (kr *KeyringStore) DeleteRoleCredentials(arn string) error {
	storage := StorageData{}
	if err := kr.getStorageData(&storage); err != nil {
		return err
	}

	if _, ok := storage.RoleCredentials[arn]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("Missing RoleCredentials for arn: %s", arn)
	}

	delete(storage.RoleCredentials, arn)
	return nil
}

func getHomePath(path string) string {
	return strings.Replace(path, "~", os.Getenv("HOME"), 1)
}
