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
	"strings"
	"time"

	"github.com/99designs/keyring"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	KEYRING_NAME                = "AWSSSOCli"
	KEYRING_ID                  = "aws-sso-cli"
	REGISTER_CLIENT_DATA_PREFIX = "client-data"
)

// Impliments SecureStorage
type KeyringCache struct {
	keyring keyring.Keyring
	config  keyring.Config
}

// https://github.com/99designs/keyring/blob/master/config.go
var krConfigDefaults = keyring.Config{
	ServiceName: KEYRING_NAME, // generic
	// OSX Keychain
	KeychainName:                   KEYRING_NAME,
	KeychainSynchronizable:         false,
	KeychainAccessibleWhenUnlocked: false,
	// KeychainPasswordFunc: ???,
	// Other systems below this line
	FileDir:                 CONFIG_DIR + "/keys/",
	FilePasswordFunc:        fileKeyringPassphrasePrompt,
	LibSecretCollectionName: strings.ToLower(KEYRING_NAME),
	KWalletAppID:            KEYRING_ID,
	KWalletFolder:           KEYRING_ID,
	WinCredPrefix:           KEYRING_ID,
}

func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password := os.Getenv(ENV_SSO_FILE_PASSWORD); password != "" {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

func OpenKeyring(cfg *keyring.Config) (*KeyringCache, error) {
	if cfg == nil {
		cfg = &krConfigDefaults
	}
	ring, err := keyring.Open(*cfg)
	if err != nil {
		return nil, err
	}
	kr := KeyringCache{
		keyring: ring,
		config:  *cfg,
	}
	return &kr, nil
}

func (kr *KeyringCache) RegisterClientKey(ssoRegion string) string {
	return fmt.Sprintf("%s:%s", REGISTER_CLIENT_DATA_PREFIX, ssoRegion)
}

// Save our RegisterClientData in the key chain
func (kr *KeyringCache) SaveRegisterClientData(region string, client RegisterClientData) error {
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
func (kr *KeyringCache) GetRegisterClientData(region string, client *RegisterClientData) error {
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
func (kr *KeyringCache) DeleteRegisterClientData(region string) error {
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
	// return kr.keyring.Remove(key)
	client := RegisterClientData{}
	client.ClientSecretExpiresAt = time.Now().Unix()
	return kr.SaveRegisterClientData(region, client)
}
