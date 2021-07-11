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
	"io/ioutil"
	"os"
	"path"

	// "github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

// Impliments SecureStorage insecurely
type JsonStore struct {
	Filename            string
	RegisterClient      map[string]RegisterClientData  `json:"RegisterClient,omitempty"`
	StartDeviceAuth     map[string]StartDeviceAuthData `json:"StartDeviceAuth,omitempty"`
	CreateTokenResponse map[string]CreateTokenResponse `json:"CreateTokenResponse,omitempty"`
	Roles               RoleCache                      `json:"Roles,omitempty"`
}

func OpenJsonStore(fileName string) (*JsonStore, error) {
	cache := JsonStore{
		Filename:            fileName,
		RegisterClient:      map[string]RegisterClientData{},
		StartDeviceAuth:     map[string]StartDeviceAuthData{},
		CreateTokenResponse: map[string]CreateTokenResponse{},
		Roles:               RoleCache{},
	}

	cacheBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Warnf("Creating new cache file: %s", fileName)
	} else {
		json.Unmarshal(cacheBytes, &cache)
	}

	return &cache, nil
}

// ensures the given directory exists for the filename
func ensureDirExists(filename string) error {
	storeDir := path.Dir(filename)
	f, err := os.Open(storeDir)
	if err != nil {
		err = os.MkdirAll(storeDir, 0700)
		if err != nil {
			return fmt.Errorf("Unable to create %s: %s", storeDir, err.Error())
		}
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("Unable to stat %s: %s", storeDir, err.Error())
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory!", storeDir)
	}
	return nil
}

// save the cache file, creating the directory if necessary
func (jc *JsonStore) saveCache() error {
	log.Debugf("Saving JSON Cache")
	jbytes, err := json.MarshalIndent(jc, "", "  ")
	if err != nil {
		log.WithError(err).Errorf("Unable to marshal json")
		return err
	}
	err = ensureDirExists(jc.Filename)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(jc.Filename, jbytes, 0600)
}

// RegisterClientData
func (jc *JsonStore) SaveRegisterClientData(key string, client RegisterClientData) error {
	jc.RegisterClient[key] = client
	return jc.saveCache()
}

func (jc *JsonStore) GetRegisterClientData(key string, client *RegisterClientData) error {
	var ok bool
	*client, ok = jc.RegisterClient[key]
	if !ok {
		return fmt.Errorf("No RegisterClientData for %s", key)
	}
	return nil
}

func (jc *JsonStore) DeleteRegisterClientData(key string) error {
	jc.RegisterClient[key] = RegisterClientData{}
	return jc.saveCache()
}

// CreateTokenResponse
func (jc *JsonStore) SaveCreateTokenResponse(key string, token CreateTokenResponse) error {
	jc.CreateTokenResponse[key] = token
	return jc.saveCache()
}

func (jc *JsonStore) GetCreateTokenResponse(key string, token *CreateTokenResponse) error {
	var ok bool
	*token, ok = jc.CreateTokenResponse[key]
	if !ok {
		return fmt.Errorf("No CreateTokenResponse for %s", key)
	}
	return nil
}

func (jc *JsonStore) DeleteCreateTokenResponse(key string) error {
	jc.CreateTokenResponse[key] = CreateTokenResponse{}
	return jc.saveCache()
}

// GetRoles reads the roles from the cache.  Returns error if missing
func (jc *JsonStore) GetRoles(roles *map[string][]RoleInfo) error {
	if jc.Roles.CreatedAt == 0 {
		return fmt.Errorf("No Roles available in cache")
	}
	*roles = jc.Roles.Roles
	return nil
}

// GetRolesExpired returns true if the roles in the cache have expired
func (jc *JsonStore) GetRolesExpired() bool {
	return jc.Roles.Expired()
}

// SaveRoles saves the roles to the cache
func (jc *JsonStore) SaveRoles(roles map[string][]RoleInfo) error {
	jc.Roles = RoleInfoCache(roles)
	return jc.saveCache()
}

// DeleteRoles removes the roles from the cache
func (jc *JsonStore) DeleteRoles() error {
	jc.Roles = RoleCache{}
	return jc.saveCache()
}
