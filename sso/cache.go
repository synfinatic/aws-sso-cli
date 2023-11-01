package sso

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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/tags"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	CACHE_VERSION      = 3
	SLOW_FETCH_SECONDS = 2 // number of seconds before notifying users
)

type SSOCache struct {
	LastUpdate int64    `json:"LastUpdate,omitempty"` // when these records for this SSO were updated
	History    []string `json:"History,omitempty"`
	Roles      *Roles   `json:"Roles,omitempty"`
	name       string   // name of this SSO Instance
}

// Our Cachefile.  Sub-structs defined in sso/cache.go
type Cache struct {
	Version         int64                `json:"Version"`
	settings        *Settings            // pointer back up
	ConfigCreatedAt int64                `json:"ConfigCreatedAt"` // track config.yaml
	SSO             map[string]*SSOCache `json:"SSO,omitempty"`
	ssoName         string               // name of SSO that is active
	refreshed       bool                 // track if we have run Refresh() since this is expensive
}

func OpenCache(f string, s *Settings) (*Cache, error) {
	cache := Cache{
		settings:        s,
		ConfigCreatedAt: 0,
		Version:         1, // use an invalid default version for cache files without a version
		SSO:             map[string]*SSOCache{},
		ssoName:         s.DefaultSSO, // default to the config file default
	}

	var err error
	var cacheBytes []byte
	if f != "" {
		cacheBytes, err = os.ReadFile(f)
		if err != nil {
			return &cache, err // return empty struct
		}
		err = json.Unmarshal(cacheBytes, &cache)
	}

	c := &cache
	c.deleteOldHistory()

	return c, err
}

// GetSSO returns the current SSOCache object for the current SSO instance
func (c *Cache) GetSSO() *SSOCache {
	if v, ok := c.SSO[c.ssoName]; ok {
		v.name = c.ssoName
		v.Roles.ssoName = c.ssoName
		return v
	}

	// else, init a new one
	c.SSO[c.ssoName] = &SSOCache{
		name:       c.ssoName,
		LastUpdate: 0,
		History:    []string{},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{},
			ssoName:  c.ssoName,
		},
	}
	return c.SSO[c.ssoName]
}

func (c *Cache) CacheFile() string {
	return c.settings.cacheFile
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
		return fmt.Errorf("Unable to marshal json: %s", err.Error())
	}
	err = utils.EnsureDirExists(c.CacheFile())
	if err != nil {
		return fmt.Errorf("Unable to create directory for %s: %s", c.CacheFile(), err.Error())
	}
	err = os.WriteFile(c.CacheFile(), jbytes, 0600)
	if err != nil {
		return fmt.Errorf("Unable to write %s: %s", c.CacheFile(), err.Error())
	}
	return nil
}

// AddHistory adds a role ARN to the History list up to the max number of entries
// and then removes the History tag from any roles that aren't in our list
func (c *Cache) AddHistory(item string) {
	// If it's already in the list, remove item
	c.deleteHistoryItem(item)

	c.GetSSO().History = append([]string{item}, c.GetSSO().History...) // push on top
	for int64(len(c.GetSSO().History)) > c.settings.HistoryLimit {
		// remove the oldest entry
		c.GetSSO().History = c.GetSSO().History[:len(c.GetSSO().History)-1]
	}

	// Update our Tags for this new item
	aId, roleName, _ := utils.ParseRoleARN(item)
	if a, ok := c.GetSSO().Roles.Accounts[aId]; ok {
		if r, ok := a.Roles[roleName]; ok {
			r.Tags["History"] = fmt.Sprintf("%s:%s,%d", a.Alias, roleName, time.Now().Unix())
		}
	}

	// remove any history tags not in our list
	roles := c.GetSSO().Roles.MatchingRolesWithTagKey("History")

	for _, role := range roles {
		exists := false
		for _, history := range c.GetSSO().History {
			if history == (*role).Arn {
				exists = true
				break
			}
		}

		// remove any History tag for roles which don't exist in c.GetSSO().History
		if !exists {
			aId, roleName, _ := utils.ParseRoleARN(role.Arn)
			delete(c.GetSSO().Roles.Accounts[aId].Roles[roleName].Tags, "History")
		}
	}
}

func (c *Cache) deleteHistoryItem(arn string) {
	for i, value := range c.GetSSO().History {
		if arn == value {
			c.GetSSO().History = append(c.GetSSO().History[:i], c.GetSSO().History[i+1:]...)
			break
		}
	}
}

// deleteOldHistory removes any items from history which are older than HistoryMinutes
// Does not actually save to disk, only updates in memory cache
func (c *Cache) deleteOldHistory() {
	if c.settings.HistoryMinutes <= 0 {
		// no op if HistoryMinutes <= 0
		return
	}

	cache := c.GetSSO()

	newHistoryItems := []string{}

	// iteratate over each ARN in our History list
	for _, arn := range cache.History {
		id, role, err := utils.ParseRoleARN(arn)
		if err != nil {
			log.Debugf("Unable to parse History ARN %s: %s", arn, err.Error())
			c.deleteHistoryItem(arn)
			continue
		}

		// for the given ARN, lookup the History tag
		if a, ok := cache.Roles.Accounts[id]; ok {
			if r, ok := a.Roles[role]; ok {
				// figure out if this history item has expired
				history, ok := r.Tags["History"]
				if !ok || history == "" {
					// doesn't have anything to expires
					log.Debugf("%s is in history list without a History tag in cache?", arn)
					c.deleteHistoryItem(arn)
					continue
				}

				values := strings.SplitN(history, ",", 2)
				if len(values) != 2 {
					log.Debugf("Too few fields for %s History Tag: '%s'", r.Arn, history)
					c.deleteHistoryItem(arn)
					continue
				}
				lastTime, err := strconv.ParseInt(values[1], 10, 64)
				if err != nil {
					log.Debugf("Unable to parse %s History Tag '%s': %s", r.Arn, history, err.Error())
					c.deleteHistoryItem(arn)
					continue
				}

				d := time.Since(time.Unix(lastTime, 0))
				if int64(d.Minutes()) < c.settings.HistoryMinutes {
					// keep current entries in our list
					newHistoryItems = append(newHistoryItems, arn)
				} else {
					// else, delete the tag and remove the item from History by
					// not appending it to newHistoryItems
					delete(r.Tags, "History")
					c.deleteHistoryItem(arn)
					log.Debugf("Removed expired history role: %s", r.Arn)
				}
			} else {
				c.deleteHistoryItem(arn)
				log.Debugf("History contains %s, but no role by that name", arn)
			}
		} else {
			c.deleteHistoryItem(arn)
			log.Debugf("History contains %s, but no account by that name", arn)
		}
	}

	c.GetSSO().History = newHistoryItems
}

// Refresh updates our cached Roles based on AWS SSO & our Config
// but does not save this data!
func (c *Cache) Refresh(sso *AWSSSO, config *SSOConfig, ssoName string, threads int) error {
	// Only refresh once per execution
	if c.refreshed {
		return nil
	}
	c.refreshed = true
	log.Debugf("refreshing %s SSO cache", ssoName)

	// save role creds expires time
	expires := map[string]int64{}
	cache := c.GetSSO()
	for _, account := range cache.Roles.Accounts {
		for _, role := range account.Roles {
			if role.Expires > 0 {
				expires[role.Arn] = role.Expires
			}
		}
	}

	// save existing History tags
	historyTags := map[string]string{}
	for _, arn := range c.SSO[ssoName].History {
		roleFlat, err := c.GetRole(arn)
		if err != nil {
			continue
		}
		if value, ok := roleFlat.Tags["History"]; ok {
			historyTags[arn] = value
		}
	}

	// zero out our current roles cache entries so they don't get merged
	c.SSO[ssoName].Roles = &Roles{}

	// load our AWSSSO & Config
	r, err := c.NewRoles(sso, config, threads)
	if err != nil {
		return err
	}
	c.SSO[ssoName].Roles = r

	// restore our history tags & expires
	for _, account := range c.SSO[ssoName].Roles.Accounts {
		for _, role := range account.Roles {
			if value, ok := historyTags[role.Arn]; ok {
				role.Tags["History"] = value
			}
			if value, ok := expires[role.Arn]; ok {
				role.Expires = value
			}
		}
	}
	c.ConfigCreatedAt = config.CreatedAt()
	return nil
}

// pruneSSO removes any SSO instances that are no longer configured
func (c *Cache) PruneSSO(settings *Settings) {
	log.Debugf("pruning our cache of outdated SSO instances")
	for sso := range c.SSO {
		hasSSO := false
		for s := range settings.SSO {
			if s == sso {
				log.Debugf("keeping %s in cache", sso)
				hasSSO = true
				break
			}
		}
		if !hasSSO {
			log.Debugf("pruning %s from cache", sso)
			delete(c.SSO, sso)
		}
	}
}

// SetRoleExpires updates the Expires time in the cache.  expires is Unix epoch time in sec
func (c *Cache) SetRoleExpires(arn string, expires int64) error {
	flat, err := c.GetRole(arn)
	if err != nil {
		return err
	}

	cache := c.GetSSO()
	cache.Roles.Accounts[flat.AccountId].Roles[flat.RoleName].Expires = expires
	return c.Save(false)
}

// MarkRolesExpired marks all IAM role credentials in the cache as expired
func (c *Cache) MarkRolesExpired() error {
	cache := c.GetSSO()
	for accountId := range cache.Roles.Accounts {
		for _, role := range cache.Roles.Accounts[accountId].Roles {
			(*role).Expires = 0
		}
	}
	return c.Save(false)
}

// returns all tags, but with with spaces replaced with underscores
func (c *Cache) GetAllTagsSelect() *tags.TagsList {
	cache := c.GetSSO()
	t := cache.Roles.GetAllTags()
	fixedTags := tags.NewTagsList()
	for k, values := range *t {
		key := strings.ReplaceAll(k, " ", "_")
		for _, v := range values {
			if key == "History" {
				v = tags.ReformatHistory(v)
			}
			fixedTags.Add(key, strings.ReplaceAll(v, " ", "_"))
		}
	}
	return fixedTags
}

// GetRoleTagsSelect returns all the tags for each role with all the spaces
// replaced with underscores
func (c *Cache) GetRoleTagsSelect() *RoleTags {
	ret := RoleTags{}
	cache := c.GetSSO()
	fList := cache.Roles.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			key := strings.ReplaceAll(k, " ", "_")
			if key == "History" {
				v = tags.ReformatHistory(v)
			}
			value := strings.ReplaceAll(v, " ", "_")
			ret[role.Arn][key] = value
		}
	}
	return &ret
}

// GetRole returns the AWSRoleFlat for the given role ARN
func (c *Cache) GetRole(arn string) (*AWSRoleFlat, error) {
	accountId, roleName, err := utils.ParseRoleARN(arn)
	if err != nil {
		return &AWSRoleFlat{}, err
	}
	cache := c.GetSSO()
	return cache.Roles.GetRole(accountId, roleName)
}

// Merges the AWS SSO and our Config file to create our Roles struct
// which is defined in cache_roles.go
func (c *Cache) NewRoles(as *AWSSSO, config *SSOConfig, threads int) (*Roles, error) {
	r := Roles{
		SSORegion:     config.SSORegion,
		StartUrl:      config.StartUrl,
		DefaultRegion: config.DefaultRegion,
		Accounts:      map[int64]*AWSAccount{},
		ssoName:       config.settings.DefaultSSO,
	}

	if err := c.addSSORoles(&r, as, threads); err != nil {
		return &Roles{}, err
	}

	if err := c.addConfigRoles(&r, config); err != nil {
		return &Roles{}, err
	}

	if err := r.checkProfiles(c.settings); err != nil {
		return &Roles{}, err
	}

	return &r, nil
}

// goroutine worker to fetch the RoleInfo for the given account
func fetchSSORole(id int, as *AWSSSO, aInfo <-chan AccountInfo, rInfo chan<- []RoleInfo) {
	for {
		a := <-aInfo
		if a.AccountId == "" {
			// need some way to exit our worker...
			break
		}
		log.Debugf("Worker %d processing AccountId: %s", id, a.AccountId)
		roles, err := as.GetRoles(a)
		if err != nil {
			log.Panicf("Unable to get AWS SSO roles: %s", err.Error())
		}
		rInfo <- roles
	}
}

// processSSORoles updates the *Roles with ith the list of RoleInfo
// and using our SSOCache
func processSSORoles(roles []RoleInfo, cache *SSOCache, r *Roles) {
	for _, role := range roles {
		log.Debugf("Processing %s:%s", role.AccountId, role.RoleName)
		accountId := role.GetAccountId64()

		if _, ok := r.Accounts[accountId]; !ok {
			r.Accounts[accountId] = &AWSAccount{
				Alias:        role.AccountName, // AWS SSO calls it `AccountName`
				EmailAddress: role.EmailAddress,
				Tags:         map[string]string{},
				Roles:        map[string]*AWSRole{},
			}
		}

		r.Accounts[accountId].Roles[role.RoleName] = &AWSRole{
			Arn: utils.MakeRoleARN(accountId, role.RoleName),
			Tags: map[string]string{
				"AccountID":    role.AccountId,
				"AccountAlias": role.AccountName, // AWS SSO calls it `AccountName`
				"Email":        role.EmailAddress,
				"Role":         role.RoleName,
			},
		}
		// need to copy over the Expires & History fields from our current cache
		if _, ok := cache.Roles.Accounts[accountId]; ok {
			if _, ok := cache.Roles.Accounts[accountId].Roles[role.RoleName]; ok {
				if expires := cache.Roles.Accounts[accountId].Roles[role.RoleName].Expires; expires > 0 {
					r.Accounts[accountId].Roles[role.RoleName].Expires = expires
				}
				if v, ok := cache.Roles.Accounts[accountId].Roles[role.RoleName].Tags["History"]; ok {
					r.Accounts[accountId].Roles[role.RoleName].Tags["History"] = v
				}
			}
		}
	}
}

// addSSORoles retrieves all the SSO Roles from AWS SSO and places them in r
func (c *Cache) addSSORoles(r *Roles, as *AWSSSO, threads int) error {
	cache := c.GetSSO()

	accounts, err := as.GetAccounts()
	if err != nil {
		return fmt.Errorf("Unable to get AWS SSO accounts: %s", err.Error())
	}

	// Our first query must NOT be part of the worker pool so our AccessToken
	// can be updated
	firstJob, accounts := accounts[0], accounts[1:]
	roles, err := as.GetRoles(firstJob)
	if err != nil {
		return err
	}
	processSSORoles(roles, cache, r)

	// Per #448, doing this serially is too slow for many accounts.  Hence,
	// we'll use a worker pool.
	if len(accounts) > 0 {
		workers := c.settings.Threads
		if threads > 0 {
			workers = threads
		}
		if workers > len(accounts) {
			workers = len(accounts)
		}

		tasks := make(chan AccountInfo, len(accounts))
		results := make(chan []RoleInfo, len(accounts))

		// feed our workers with our other accounts
		for _, aInfo := range accounts {
			tasks <- aInfo
		}
		close(tasks)

		// start our workers...
		for w := 1; w <= workers; w++ {
			go fetchSSORole(w, as, tasks, results)
		}

		// Notify
		ticker := time.NewTicker(SLOW_FETCH_SECONDS * time.Second)

		for count := 0; count < len(accounts); {
			select {
			case roles := <-results:
				processSSORoles(roles, cache, r)
				count++ // increment count only when processing results
				log.Debugf("proccessed %d accounts, added %d roles, total %d", count, len(roles), len(r.GetAllRoles()))
			case <-ticker.C:
				log.Warnf("Fetching roles for %d accounts, this might take a while...\n", len(accounts)+1)
				ticker.Stop()
			}
		}
		close(results)
	}
	return nil
}

// addConfigRoles decorates the provided Roles with the contents of our config
func (c *Cache) addConfigRoles(r *Roles, config *SSOConfig) error {
	// The load all the Config file stuff.  Normally this is just adding markup, but
	// for accounts &roles that are not in SSO, we may be creating them as well!
	for accountId, account := range config.Accounts {
		id, err := utils.AccountIdToInt64(accountId)
		if err != nil {
			return err
		}
		if _, ok := r.Accounts[id]; !ok {
			r.Accounts[id] = &AWSAccount{
				Tags:  map[string]string{},
				Roles: map[string]*AWSRole{},
			}
		}
		r.Accounts[id].DefaultRegion = account.DefaultRegion
		r.Accounts[id].Name = account.Name

		// set our account tags
		for k, v := range config.Accounts[accountId].Tags {
			r.Accounts[id].Tags[k] = v
		}

		// set the AWS SSO tags for all the SSO roles
		for roleName := range r.Accounts[id].Roles {
			aId, _ := utils.AccountIdToString(id)
			r.Accounts[id].Roles[roleName].Tags["AccountID"] = aId
			r.Accounts[id].Roles[roleName].Tags["AccountAlias"] = r.Accounts[id].Alias
			r.Accounts[id].Roles[roleName].Tags["Email"] = r.Accounts[id].EmailAddress
			r.Accounts[id].Roles[roleName].Tags["Role"] = roleName
			if r.Accounts[id].Name != "" {
				r.Accounts[id].Roles[roleName].Tags["AccountName"] = r.Accounts[id].Name
			}
			if r.Accounts[id].Roles[roleName].DefaultRegion != "" {
				r.Accounts[id].Roles[roleName].Tags["DefaultRegion"] = r.Accounts[id].Roles[roleName].DefaultRegion
			}
		}

		// set the tags from the config file
		for roleName, role := range config.Accounts[accountId].Roles {
			if _, ok := r.Accounts[id].Roles[roleName]; !ok {
				r.Accounts[id].Roles[roleName] = &AWSRole{
					Tags: map[string]string{},
				}
			}
			r.Accounts[id].Roles[roleName].Arn = utils.MakeRoleARN(id, roleName)
			r.Accounts[id].Roles[roleName].Profile = role.Profile
			r.Accounts[id].Roles[roleName].DefaultRegion = r.Accounts[id].DefaultRegion
			r.Accounts[id].Roles[roleName].Via = role.Via
			if role.DefaultRegion != "" {
				r.Accounts[id].Roles[roleName].DefaultRegion = role.DefaultRegion
			}
			// Copy the account tags to the role
			for k, v := range config.Accounts[accountId].Tags {
				r.Accounts[id].Roles[roleName].Tags[k] = v
			}
			// Insert role specific tags (possible overwrite of account level)
			for k, v := range role.Tags {
				r.Accounts[id].Roles[roleName].Tags[k] = v
			}
		}
	}
	return nil
}
