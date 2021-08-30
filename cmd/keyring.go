package main

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
	"strings"
	"time"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	KEYRING_NAME                 = "AWSSSOCli"
	KEYRING_ID                   = "aws-sso-cli"
	REGISTER_CLIENT_DATA_PREFIX  = "client-data"
	CREATE_TOKEN_RESPONSE_PREFIX = "token-response"
)

// Impliments SecureStorage
type KeyringStore struct {
	keyring keyring.Keyring
	config  keyring.Config
}

var NewPassword string = ""

func NewKeyringConfig(name string) *keyring.Config {
	securePath := path.Join(CONFIG_DIR, "secure")

	c := keyring.Config{
		ServiceName: KEYRING_NAME, // generic
		// OSX Keychain
		KeychainName:                   KEYRING_NAME,
		KeychainSynchronizable:         false,
		KeychainAccessibleWhenUnlocked: false,
		// KeychainPasswordFunc: ???,
		// Other systems below this line
		FileDir:                 securePath,
		FilePasswordFunc:        fileKeyringPassphrasePrompt,
		LibSecretCollectionName: strings.ToLower(KEYRING_NAME),
		KWalletAppID:            KEYRING_ID,
		KWalletFolder:           KEYRING_ID,
		WinCredPrefix:           KEYRING_ID,
	}
	if name != "" {
		c.AllowedBackends = []keyring.BackendType{keyring.BackendType(name)}
		rolesFile := GetPath(path.Join(securePath, "roles"))

		if name == "file" {
			if _, err := os.Stat(rolesFile); os.IsNotExist(err) {
				// new secure store, so we should prompt user twice for password
				// if ENV var is not set
				if password := os.Getenv(ENV_SSO_FILE_PASSWORD); password == "" {
					pass1, err := fileKeyringPassphrasePrompt("Select password")
					if err != nil {
						log.Fatalf("Password error: %s", err.Error())
					}
					pass2, err := fileKeyringPassphrasePrompt("Verify password")
					if err != nil {
						log.Fatalf("Password error: %s", err.Error())
					}
					if pass1 != pass2 {
						log.Fatalf("Password missmatch")
					}
					NewPassword = pass1
				}
			}
		}
	}
	return &c
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
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
	fmt.Println()
	return string(b), nil
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

// Save our RegisterClientData in the key chain
func (kr *KeyringStore) SaveRegisterClientData(region string, client sso.RegisterClientData) error {
	jdata, err := json.Marshal(client)
	if err != nil {
		return err
	}
	err = kr.keyring.Set(keyring.Item{
		Key:  kr.RegisterClientKey(region),
		Data: jdata,
	})
	return err
}

// Get our RegisterClientData from the key chain
func (kr *KeyringStore) GetRegisterClientData(region string, client *sso.RegisterClientData) error {
	data, err := kr.keyring.Get(kr.RegisterClientKey(region))
	if err != nil {
		return err
	}
	err = json.Unmarshal(data.Data, client)
	if err != nil {
		return err
	}
	return nil
}

// Delete the RegisterClientData from the keychain
func (kr *KeyringStore) DeleteRegisterClientData(region string) error {
	keys, err := kr.keyring.Keys()
	if err != nil {
		return err
	}

	// make sure we have this profile stored
	hasKey := false
	key := kr.RegisterClientKey(region)
	for _, k := range keys {
		if k == key {
			hasKey = true
			break
		}
	}
	if !hasKey {
		return fmt.Errorf("Missing client data for region: %s", region)
	}

	// Can't just call keyring.Remove() because it's broken, so we'll update the record instead
	// https://github.com/99designs/keyring/issues/84
	// return kr.keyring.Remove(key)
	client := sso.RegisterClientData{}
	client.ClientSecretExpiresAt = time.Now().Unix()
	return kr.SaveRegisterClientData(region, client)
}

func (kr *KeyringStore) CreateTokenResponseKey(key string) string {
	return fmt.Sprintf("%s:%s", CREATE_TOKEN_RESPONSE_PREFIX, key)
}

// SaveCreateTokenResponse stores the token in the keyring
func (kr *KeyringStore) SaveCreateTokenResponse(key string, token sso.CreateTokenResponse) error {
	jdata, err := json.Marshal(token)
	if err != nil {
		return err
	}
	err = kr.keyring.Set(keyring.Item{
		Key:  kr.CreateTokenResponseKey(key),
		Data: jdata,
	})
	return err
}

// GetCreateTokenResponse retrieves the CreateTokenResponse from the keyring
func (kr *KeyringStore) GetCreateTokenResponse(key string, token *sso.CreateTokenResponse) error {
	data, err := kr.keyring.Get(kr.CreateTokenResponseKey(key))
	if err != nil {
		return err
	}
	err = json.Unmarshal(data.Data, token)
	if err != nil {
		return err
	}
	return nil
}

// DeleteCreateTokenResponse deletes the CreateTokenResponse from the keyring
func (kr *KeyringStore) DeleteCreateTokenResponse(key string) error {
	keys, err := kr.keyring.Keys()
	if err != nil {
		return err
	}

	// make sure we have this token response store
	hasKey := false
	keyValue := kr.CreateTokenResponseKey(key)
	for _, k := range keys {
		if k == keyValue {
			hasKey = true
			break
		}
	}
	if !hasKey {
		return fmt.Errorf("Missing CreateTokenResponse for key: %s", key)
	}

	// Can't just call keyring.Remove because it's broken, so we'll udpate the record instead
	// https://github.com/99designs/keyring/issues/84
	// return kr.keyring.Remove(keyValue)
	tr := sso.CreateTokenResponse{}
	tr.ExpiresAt = time.Now().Unix()
	return kr.SaveCreateTokenResponse(key, tr)
}
