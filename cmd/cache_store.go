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
	"time"

	log "github.com/sirupsen/logrus"
)

type HistoryCache struct {
	Roles []string
}

type RoleCache struct {
	CreatedAt int64                 `json:"CreatedAt"`
	Roles     map[string][]RoleInfo `json:"Roles"`
}

// used to store information that is not confidential
type CacheStore struct {
	filename string
	History  HistoryCache `json:"History,omitempty"`
	Roles    RoleCache    `json:"Roles,omitempty"`
}

// RoleCache
// Returns true or false if the RoleInfoCache has expired
func (rc *RoleCache) Expired() bool {
	if rc.CreatedAt+CACHE_TTL < time.Now().Unix() {
		return true
	}
	return false
}

// Converts the map of RoleInfo into a cache
func RoleInfoCache(roles map[string][]RoleInfo) RoleCache {
	cache := RoleCache{
		CreatedAt: time.Now().Unix(),
		Roles:     roles,
	}
	return cache
}

// CacheStore
func OpenCacheStore(fileName string) (*CacheStore, error) {
	cache := CacheStore{
		filename: fileName,
		History:  HistoryCache{},
		Roles:    RoleCache{},
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
func (cs *CacheStore) SaveCache() error {
	log.Debugf("Saving CacheStore cache")
	jbytes, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		log.WithError(err).Errorf("Unable to marshal json")
		return err
	}
	err = ensureDirExists(cs.filename)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(cs.filename, jbytes, 0600)
}

// GetRoles reads the roles from the cache.  Returns error if missing
func (cs *CacheStore) GetRoles(roles *map[string][]RoleInfo) error {
	if cs.Roles.CreatedAt == 0 {
		return fmt.Errorf("No Roles available in cache")
	}
	*roles = cs.Roles.Roles
	return nil
}

// GetRolesExpired returns true if the roles in the cache have expired
func (cs *CacheStore) GetRolesExpired() bool {
	return cs.Roles.Expired()
}

// SaveRoles saves the roles to the cache
func (cs *CacheStore) SaveRoles(roles map[string][]RoleInfo) error {
	cs.Roles = RoleInfoCache(roles)
	return cs.SaveCache()
}

// DeleteRoles removes the roles from the cache
func (cs *CacheStore) DeleteRoles() error {
	cs.Roles = RoleCache{}
	return cs.SaveCache()
}

// adds a role to the history list up to the max number of entries
func (cs *CacheStore) AddHistory(item string, max int) {
	cs.History.Roles = append([]string{item}, cs.History.Roles...) // push on top
	for len(cs.History.Roles) > max {
		// remove the oldest entry
		cs.History.Roles = cs.History.Roles[:len(cs.History.Roles)-1]
	}
}
