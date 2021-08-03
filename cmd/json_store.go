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

	// "github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

// Impliments SecureStorage insecurely
type JsonStore struct {
	filename            string
	RegisterClient      map[string]RegisterClientData  `json:"RegisterClient,omitempty"`
	StartDeviceAuth     map[string]StartDeviceAuthData `json:"StartDeviceAuth,omitempty"`
	CreateTokenResponse map[string]CreateTokenResponse `json:"CreateTokenResponse,omitempty"`
}

func OpenJsonStore(fileName string) (*JsonStore, error) {
	cache := JsonStore{
		filename:            fileName,
		RegisterClient:      map[string]RegisterClientData{},
		StartDeviceAuth:     map[string]StartDeviceAuthData{},
		CreateTokenResponse: map[string]CreateTokenResponse{},
	}

	cacheBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Warnf("Creating new cache file: %s", fileName)
	} else {
		json.Unmarshal(cacheBytes, &cache)
	}

	return &cache, nil
}

// save the cache file, creating the directory if necessary
func (jc *JsonStore) saveCache() error {
	log.Debugf("Saving JSON Cache")
	jbytes, err := json.MarshalIndent(jc, "", "  ")
	if err != nil {
		log.WithError(err).Errorf("Unable to marshal json")
		return err
	}
	err = ensureDirExists(jc.filename)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(jc.filename, jbytes, 0600)
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

// SaveCreateTokenResponse stores the token in the json file
func (jc *JsonStore) SaveCreateTokenResponse(key string, token CreateTokenResponse) error {
	jc.CreateTokenResponse[key] = token
	return jc.saveCache()
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
	jc.CreateTokenResponse[key] = CreateTokenResponse{}
	return jc.saveCache()
}
