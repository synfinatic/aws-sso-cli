package storage

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"errors"
	"fmt"
	"io/fs"
	"os"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

// JsonStore implements SecureStorage insecurely
type JsonStore struct {
	filename            string
	RegisterClient      map[string]RegisterClientData  `json:"RegisterClient,omitempty"`
	StartDeviceAuth     map[string]StartDeviceAuthData `json:"StartDeviceAuth,omitempty"`
	CreateTokenResponse map[string]CreateTokenResponse `json:"CreateTokenResponse,omitempty"`
	RoleCredentials     map[string]RoleCredentials     `json:"RoleCredentials,omitempty"`   // ARN = key
	StaticCredentials   map[string]StaticCredentials   `json:"StaticCredentials,omitempty"` // ARN = key
	EcsBearerToken      string                         `json:"EcsBearerToken,omitempty"`
	EcsPrivateKey       string                         `json:"EcsPrivateKey,omitempty"`
	EcsCertChain        string                         `json:"EcsCertChain,omitempty"`
}

// OpenJsonStore opens our insecure JSON storage backend
func OpenJsonStore(filename string) (*JsonStore, error) {
	cache := JsonStore{
		filename:            filename,
		RegisterClient:      map[string]RegisterClientData{},
		StartDeviceAuth:     map[string]StartDeviceAuthData{},
		CreateTokenResponse: map[string]CreateTokenResponse{},
		RoleCredentials:     map[string]RoleCredentials{},
		StaticCredentials:   map[string]StaticCredentials{},
		EcsBearerToken:      "",
		EcsPrivateKey:       "",
		EcsCertChain:        "",
	}

	cacheBytes, err := os.ReadFile(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return &cache, nil
	} else if err != nil {
		return &cache, fmt.Errorf("unable to open %s: %s", filename, err.Error())
	}

	if len(cacheBytes) > 0 {
		err = json.Unmarshal(cacheBytes, &cache)
	}

	return &cache, err
}

// save writes the JSON store file, creating the directory if necessary
func (jc *JsonStore) save() error {
	log.Debugf("Saving JSON Cache")
	jbytes, err := json.MarshalIndent(jc, "", "  ")
	if err != nil {
		log.WithError(err).Errorf("Unable to marshal json")
		return err
	}

	err = utils.EnsureDirExists(jc.filename)
	if err != nil {
		return err
	}

	return os.WriteFile(jc.filename, jbytes, 0600)
}

// SaveRegisterClientData saves the RegisterClientData in our JSON store
func (jc *JsonStore) SaveRegisterClientData(key string, client RegisterClientData) error {
	jc.RegisterClient[key] = client
	return jc.save()
}

// GetRegisterClientData retrieves the RegisterClientData from our JSON store
func (jc *JsonStore) GetRegisterClientData(key string, client *RegisterClientData) error {
	var ok bool
	*client, ok = jc.RegisterClient[key]
	if !ok {
		return fmt.Errorf("No RegisterClientData for %s", key)
	}
	return nil
}

// DeleteRegisterClientData deletes the RegisterClientData from the JSON store
func (jc *JsonStore) DeleteRegisterClientData(key string) error {
	delete(jc.RegisterClient, key)
	return jc.save()
}

// SaveCreateTokenResponse stores the token in the json file
func (jc *JsonStore) SaveCreateTokenResponse(key string, token CreateTokenResponse) error {
	jc.CreateTokenResponse[key] = token
	return jc.save()
}

// GetCreateTokenResponse retrieves the CreateTokenResponse from the json file
func (jc *JsonStore) GetCreateTokenResponse(key string, token *CreateTokenResponse) error {
	var ok bool
	*token, ok = jc.CreateTokenResponse[key]
	if !ok {
		return fmt.Errorf("No CreateTokenResponse for %s", key)
	}
	return nil
}

// DeleteCreateTokenResponse deletes the token from the json file
func (jc *JsonStore) DeleteCreateTokenResponse(key string) error {
	delete(jc.CreateTokenResponse, key)
	return jc.save()
}

// SaveRoleCredentials stores the token in the json file
func (jc *JsonStore) SaveRoleCredentials(arn string, token RoleCredentials) error {
	jc.RoleCredentials[arn] = token
	return jc.save()
}

// GetRoleCredentials retrieves the RoleCredentials from the json file
func (jc *JsonStore) GetRoleCredentials(arn string, token *RoleCredentials) error {
	var ok bool
	*token, ok = jc.RoleCredentials[arn]
	if !ok {
		return fmt.Errorf("No RoleCredentials for ARN: %s", arn)
	}
	return nil
}

// DeleteRoleCredentials deletes the token from the json file
func (jc *JsonStore) DeleteRoleCredentials(arn string) error {
	delete(jc.RoleCredentials, arn)
	return jc.save()
}

// SaveStaticCredentials stores the token in the json file
func (jc *JsonStore) SaveStaticCredentials(arn string, creds StaticCredentials) error {
	jc.StaticCredentials[arn] = creds
	return jc.save()
}

// GetStaticCredentials retrieves the StaticCredentials from the json file
func (jc *JsonStore) GetStaticCredentials(arn string, creds *StaticCredentials) error {
	var ok bool
	*creds, ok = jc.StaticCredentials[arn]
	if !ok {
		return fmt.Errorf("No StaticCredentials for ARN: %s", arn)
	}
	return nil
}

// DeleteStaticCredentials deletes the StaticCredentials from the json file
func (jc *JsonStore) DeleteStaticCredentials(arn string) error {
	if _, ok := jc.StaticCredentials[arn]; !ok {
		// return error if key doesn't exist
		return fmt.Errorf("No StaticCredentials for ARN: %s", arn)
	}

	delete(jc.StaticCredentials, arn)
	return jc.save()
}

// ListStaticCredentials returns all the ARN's of static credentials
func (jc *JsonStore) ListStaticCredentials() []string {
	ret := make([]string, len(jc.StaticCredentials))
	i := 0
	for k := range jc.StaticCredentials {
		ret[i] = k
		i++
	}
	return ret
}

// SaveEcsBearerToken stores the token in the json file
func (jc *JsonStore) SaveEcsBearerToken(token string) error {
	jc.EcsBearerToken = token
	return jc.save()
}

// GetEcsBearerToken retrieves the token from the json file
func (jc *JsonStore) GetEcsBearerToken() (string, error) {
	return jc.EcsBearerToken, nil
}

// DeleteEcsBearerToken deletes the token from the json file
func (jc *JsonStore) DeleteEcsBearerToken() error {
	jc.EcsBearerToken = ""
	return jc.save()
}

// SaveEcsSslKeyPair stores the SSL private key and certificate chain in the json file
func (jc *JsonStore) SaveEcsSslKeyPair(privateKey, certChain []byte) error {
	if err := ValidateSSLCertificate(certChain); err != nil {
		return err
	}
	jc.EcsCertChain = string(certChain)

	if err := ValidateSSLPrivateKey(privateKey); err != nil {
		return err
	}
	jc.EcsPrivateKey = string(privateKey)
	return jc.save()
}

// GetEcsSslCert retrieves the SSL certificate chain from the json file
func (jc *JsonStore) GetEcsSslCert() (string, error) {
	return jc.EcsCertChain, nil
}

// GetEcsSslKey retrieves the SSL private keyfrom the json file
func (jc *JsonStore) GetEcsSslKey() (string, error) {
	return jc.EcsPrivateKey, nil
}

// DeleteEcsSslKeyPair deletes the SSL private key and certificate chain from the json file
func (jc *JsonStore) DeleteEcsSslKeyPair() error {
	jc.EcsPrivateKey = ""
	jc.EcsCertChain = ""
	return jc.save()
}
