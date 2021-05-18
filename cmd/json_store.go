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

	log "github.com/sirupsen/logrus"
)

// Impliments SecureStorage insecurely
type JsonStore struct {
	Filename        string
	registerClient  map[string]RegisterClientData  `json:"RegisterClient"`
	startDeviceAuth map[string]StartDeviceAuthData `json:"StartDeviceAuth"`
}

func OpenJsonStore(fileName string) (*JsonStore, error) {
	cache := JsonStore{
		Filename: fileName,
	}

	cacheBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Warnf("Creating new cache file: %s", fileName)
	} else {
		json.Unmarshal(cacheBytes, &cache)
	}

	return &cache, nil
}

func (jc *JsonStore) saveCache() error {
	jbytes, err := json.Marshal(jc)
	if err != nil {
		log.WithError(err).Errorf("Unable to marshal json")
		return err
	}

	return ioutil.WriteFile(jc.Filename, jbytes, 0600)
}

// RegisterClientData
func (jc *JsonStore) SaveRegisterClientData(key string, client RegisterClientData) error {
	jc.registerClient[key] = client
	return jc.saveCache()
}

func (jc *JsonStore) GetRegisterClientData(key string, client *RegisterClientData) error {
	var ok bool
	*client, ok = jc.registerClient[key]
	if !ok {
		return fmt.Errorf("No RegisterClientData for %s", key)
	}
	return nil
}

func (jc *JsonStore) DeleteRegisterClientData(key string) error {
	jc.registerClient[key] = RegisterClientData{}
	return jc.saveCache()
}

// StartDeviceAuthData
func (jc *JsonStore) SaveStartDeviceAuthData(key string, data StartDeviceAuthData) error {
	jc.startDeviceAuth[key] = data
	return jc.saveCache()
}

func (jc *JsonStore) GetStartDeviceAuthData(key string, data *StartDeviceAuthData) error {
	var ok bool
	*data, ok = jc.startDeviceAuth[key]
	if !ok {
		return fmt.Errorf("No StartDeviceAuthData for %s", key)
	}
	return nil
}

func (jc *JsonStore) DeleteStartDeviceAuthData(key string) error {
	jc.startDeviceAuth[key] = StartDeviceAuthData{}
	return jc.saveCache()
}
