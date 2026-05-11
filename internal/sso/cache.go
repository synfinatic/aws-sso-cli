package sso

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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
)

const (
	CACHE_VERSION = 4
)

type SSOCache struct {
	LastUpdate int64    `json:"LastUpdate,omitempty"` // when these records for this SSO were updated
	ConfigHash string   `json:"ConfigHash,omitempty"` // SHA256 of ProfileName + SSOConfig.Accounts
	History    []string `json:"History,omitempty"`
	Roles      *Roles   `json:"Roles,omitempty"`
	name       string   // name of this SSO Instance
}

// Our Cachefile.  Sub-structs defined in sso/cache.go
type Cache struct {
	Version         int64                `json:"Version"`
	cacheFile       string               // path to the cache file
	ConfigCreatedAt int64                `json:"ConfigCreatedAt"` // track config.yaml
	SSO             map[string]*SSOCache `json:"SSO,omitempty"`
	ssoName         string               // name of SSO that is active
	refreshed       bool                 // track if we have run Refresh() since this is expensive
}

func (c *Cache) GetSSOByName(name string) *SSOCache {
	if v, ok := c.SSO[name]; ok {
		return v
	}
	// else, init a new one
	c.SSO[name] = &SSOCache{
		name:       c.ssoName,
		LastUpdate: 0,
		History:    []string{},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{},
			SSOName:  c.ssoName,
		},
	}
	return c.SSO[name]
}

func OpenCache(f string, s *Settings) (*Cache, error) {
	cache := Cache{
		cacheFile:       f,
		ConfigCreatedAt: 0,
		Version:         1, // use an invalid default version for cache files without a version
		SSO:             map[string]*SSOCache{},
		ssoName:         s.DefaultSSO, // default to the config file default
	}

	var err error
	var cacheBytes []byte
	if f != "" {
		cacheBytes, err = os.ReadFile(f) // nolint:gosec
		if err != nil {
			return &cache, err // return empty struct
		}
		err = json.Unmarshal(cacheBytes, &cache)
		if err == nil {
			cache.cacheFile = f // restore after unmarshal (not in JSON)
		}
	}

	c := &cache
	c.deleteOldHistory(s)

	return c, err
}

// GetSSO returns the current SSOCache object for the current SSO instance
func (c *Cache) GetSSO() *SSOCache {
	if v, ok := c.SSO[c.ssoName]; ok {
		v.name = c.ssoName
		v.Roles.SSOName = c.ssoName
		return v
	}

	// else, init a new one
	c.SSO[c.ssoName] = &SSOCache{
		name:       c.ssoName,
		LastUpdate: 0,
		History:    []string{},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{},
			SSOName:  c.ssoName,
		},
	}
	return c.SSO[c.ssoName]
}

// Expired returns if our Roles cache data is too old.
// If configFile is a valid file, we check the lastModificationTime of that file
// vs. the ConfigCreatedAt to determine if the cache needs to be updated
func (c *Cache) Expired(s *SSOConfig) error {
	if c.Version < CACHE_VERSION {
		return fmt.Errorf("local cache is out of date; current cache version %d is less than %d", c.Version, CACHE_VERSION)
	}

	// negative values disable refresh
	if s.CacheRefresh <= 0 {
		return nil
	}

	ttl := s.CacheRefresh * 60 * 60 // convert hours to seconds
	cache := c.GetSSO()
	if cache.LastUpdate+ttl < time.Now().Unix() {
		return fmt.Errorf("local cache is out of date; TTL has been exceeded")
	}

	if s.CreatedAt() > c.ConfigCreatedAt {
		return fmt.Errorf("local cache is out of date; config.yaml modified")
	}
	return nil
}

func (c *Cache) CacheFile() string {
	return c.cacheFile
}

// Save saves our cache to the current file
func (c *Cache) Save(updateTime bool) error {
	c.Version = CACHE_VERSION
	if updateTime {
		cache := c.GetSSO()
		cache.LastUpdate = time.Now().Unix()
	}
	jbytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal json: %s", err.Error())
	}
	err = fileutils.EnsureDirExists(c.CacheFile())
	if err != nil {
		return fmt.Errorf("unable to create directory for %s: %s", c.CacheFile(), err.Error())
	}
	err = os.WriteFile(c.CacheFile(), jbytes, 0600)
	if err != nil {
		return fmt.Errorf("unable to write %s: %s", c.CacheFile(), err.Error())
	}
	return nil
}

// Check to see if our cache needs to be refreshed
func (c *SSOCache) NeedsRefresh(s *SSOConfig, settings *Settings) bool {
	checkHash := s.GetConfigHash(settings.ProfileFormat)
	return checkHash != c.ConfigHash
}

// pruneSSO removes any SSO instances that are no longer configured
func (c *Cache) PruneSSO(settings *Settings) {
	log.Debug("pruning our cache of outdated SSO instances")
	for sso := range c.SSO {
		hasSSO := false
		for s := range settings.SSO {
			if s == sso {
				log.Debug("keeping in cache", "SSOName", sso)
				hasSSO = true
				break
			}
		}
		if !hasSSO {
			log.Debug("pruning from cache", "SSOName", sso)
			delete(c.SSO, sso)
		}
	}
}
