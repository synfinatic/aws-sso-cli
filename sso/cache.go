package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"reflect"
	"strconv"
	"strings"
	"time"

	// "github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
	"github.com/synfinatic/gotable"
)

const CACHE_VERSION = 2

// Our Cachefile.  Sub-structs defined in sso/cache.go
type Cache struct {
	Version         int64     `json:"Version"`
	settings        *Settings // pointer back up
	CreatedAt       int64     `json:"CreatedAt"`       // this cache.json
	ConfigCreatedAt int64     `json:"ConfigCreatedAt"` // track config.yaml
	History         []string  `json:"History,omitempty"`
	Roles           *Roles    `json:"Roles,omitempty"`
}

func OpenCache(f string, s *Settings) (*Cache, error) {
	cache := Cache{
		settings:        s,
		CreatedAt:       0,
		ConfigCreatedAt: 0,
		History:         []string{},
		Version:         1, // use an invalid default version for cache files without a version
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{},
		},
	}
	var err error
	var cacheBytes []byte
	if f != "" {
		cacheBytes, err = ioutil.ReadFile(f)
		if err != nil {
			return &cache, err // return empty struct
		}
		err = json.Unmarshal(cacheBytes, &cache)
	}

	c := &cache
	c.deleteOldHistory()

	return c, err
}

// Expired returns if our Roles cache data is too old.
// If configFile is a valid file, we check the lastModificationTime of that file
// vs. the ConfigCreatedAt to determine if the cache needs to be updated
func (c *Cache) Expired(s *SSOConfig) error {
	if c.Version < CACHE_VERSION {
		return fmt.Errorf("Local cache is out of date; current cache version %d is less than %d", c.Version, CACHE_VERSION)
	}

	if c.CreatedAt+CACHE_TTL < time.Now().Unix() {
		return fmt.Errorf("Local cache is out of date; TTL has been exceeded.")
	}

	if s.CreatedAt() > c.ConfigCreatedAt {
		return fmt.Errorf("Local cache is out of date; config.yaml modified.")
	}
	return nil
}

func (c *Cache) CacheFile() string {
	return c.settings.cacheFile
}

// Save saves our cache to the current file
func (c *Cache) Save(updateTime bool) error {
	c.Version = CACHE_VERSION
	if updateTime {
		c.CreatedAt = time.Now().Unix()
	}
	jbytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	err = utils.EnsureDirExists(c.CacheFile())
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.CacheFile(), jbytes, 0600)
}

// adds a role to the History list up to the max number of entries
// and then removes the History tag from any roles that aren't in our list
func (c *Cache) AddHistory(item string) {
	// If it's already in the list, remove it
	for x, h := range c.History {
		if h == item {
			// delete from history
			c.History = append(c.History[:x], c.History[x+1:]...)
			break
		}
	}

	c.History = append([]string{item}, c.History...) // push on top
	for int64(len(c.History)) > c.settings.HistoryLimit {
		// remove the oldest entry
		c.History = c.History[:len(c.History)-1]
	}

	// Update our Tags for this new item
	aId, roleName, _ := utils.ParseRoleARN(item)
	if a, ok := c.Roles.Accounts[aId]; ok {
		if r, ok := a.Roles[roleName]; ok {
			r.Tags["History"] = fmt.Sprintf("%s:%s,%d", a.Alias, roleName, time.Now().Unix())
		}
	}

	// remove any history tags not in our list
	roles := c.Roles.MatchingRolesWithTagKey("History")
	for _, role := range roles {
		exists := false
		for _, history := range c.History {
			if history == (*role).Arn {
				exists = true
				break
			}
		}
		if !exists {
			aId, roleName, _ := utils.ParseRoleARN(role.Arn)
			delete(c.Roles.Accounts[aId].Roles[roleName].Tags, "History")
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

	newHistoryItems := []string{}
	for _, arn := range c.History {
		id, role, err := utils.ParseRoleARN(arn)
		if err != nil {
			log.Errorf("Unable to parse History ARN %s: %s", arn, err.Error())
			continue
		}

		if a, ok := c.Roles.Accounts[id]; ok {
			if r, ok := a.Roles[role]; ok {
				// figure out if this history item has expired
				values := strings.SplitN(r.Tags["History"], ",", 2)
				lastTime, err := strconv.ParseInt(values[1], 10, 64)
				if err != nil {
					log.Errorf("Unable to parse History Tag '%s': %s", r.Tags["History"], err.Error())
					continue
				}

				d := time.Since(time.Unix(lastTime, 0))
				if int64(d.Minutes()) < c.settings.HistoryMinutes {
					// keep current entries in our list
					newHistoryItems = append(newHistoryItems, arn)
				} else {
					// else, delete the tag
					delete(r.Tags, "History")
				}
			}
		}
	}

	c.History = newHistoryItems
}

// Refresh updates our cached Roles based on AWS SSO & our Config
// but does not save this data!
func (c *Cache) Refresh(sso *AWSSSO, config *SSOConfig) error {
	r, err := c.NewRoles(sso, config)
	if err != nil {
		return err
	}
	c.Roles = r
	c.ConfigCreatedAt = config.CreatedAt()
	return nil
}

// Update the Expires time in the cache.  expires is Unix epoch time in sec
func (c *Cache) SetRoleExpires(arn string, expires int64) error {
	accountId, roleName, err := utils.ParseRoleARN(arn)
	if err != nil {
		return err
	}

	c.Roles.Accounts[accountId].Roles[roleName].Expires = expires
	return c.Save(false)
}

func (c *Cache) MarkRolesExpired() error {
	for accountId := range c.Roles.Accounts {
		for _, role := range c.Roles.Accounts[accountId].Roles {
			(*role).Expires = 0
		}
	}
	return c.Save(false)
}

func (c *Cache) GetRole(arn string) (*AWSRoleFlat, error) {
	accountId, roleName, err := utils.ParseRoleARN(arn)
	if err != nil {
		return &AWSRoleFlat{}, err
	}
	return c.Roles.GetRole(accountId, roleName)
}

// main struct holding all our Roles discovered via AWS SSO and
// via the config.yaml
type Roles struct {
	Accounts      map[int64]*AWSAccount `json:"Accounts"`
	SSORegion     string                `json:"SSORegion"`
	StartUrl      string                `json:"StartUrl"`
	DefaultRegion string                `json:"DefaultRegion"`
}

// AWSAccount and AWSRole is how we store the data
type AWSAccount struct {
	Alias         string              `json:"Alias,omitempty"` // from AWS
	Name          string              `json:"Name,omitempty"`  // from config
	EmailAddress  string              `json:"EmailAddress,omitempty"`
	Tags          map[string]string   `json:"Tags,omitempty"`
	Roles         map[string]*AWSRole `json:"Roles,omitempty"`
	DefaultRegion string              `json:"DefaultRegion,omitempty"`
}

type AWSRole struct {
	Arn           string            `json:"Arn"`
	DefaultRegion string            `json:"DefaultRegion,omitempty"`
	Expires       int64             `json:"Expires,omitempty"` // Seconds since Unix Epoch
	Profile       string            `json:"Profile,omitempty"`
	Tags          map[string]string `json:"Tags,omitempty"`
	Via           string            `json:"Via,omitempty"`
}

// This is what we always return for a role definition
type AWSRoleFlat struct {
	Id            int               `header:"Id"`
	AccountId     int64             `json:"AccountId" header:"AccountId"`
	AccountName   string            `json:"AccountName" header:"AccountName"`
	AccountAlias  string            `json:"AccountAlias" header:"AccountAlias"`
	EmailAddress  string            `json:"EmailAddress" header:"EmailAddress"`
	Expires       int64             `json:"Expires" header:"ExpiresEpoch"`
	ExpiresStr    string            `json:"-" header:"Expires"`
	Arn           string            `json:"Arn" header:"ARN"`
	RoleName      string            `json:"RoleName" header:"Role"`
	Profile       string            `json:"Profile" header:"Profile"`
	DefaultRegion string            `json:"DefaultRegion" header:"DefaultRegion"`
	SSORegion     string            `json:"SSORegion" header:"SSORegion"`
	StartUrl      string            `json:"StartUrl" header:"StartUrl"`
	Tags          map[string]string `json:"Tags"` // not supported by GenerateTable
	Via           string            `json:"Via,omitempty" header:"Via"`
	// SelectTags    map[string]string // tags without spaces
}

func (f AWSRoleFlat) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(f)
	return gotable.GetHeaderTag(v, fieldName)
}

// Merges the AWS SSO and our Config file to create our Roles struct
func (c *Cache) NewRoles(as *AWSSSO, config *SSOConfig) (*Roles, error) {
	r := Roles{
		SSORegion:     config.SSORegion,
		StartUrl:      config.StartUrl,
		DefaultRegion: config.DefaultRegion,
		Accounts:      map[int64]*AWSAccount{},
	}

	// First go through all the AWS SSO Accounts & Roles
	accounts, err := as.GetAccounts()
	if err != nil {
		return &r, fmt.Errorf("Unable to get AWS SSO accounts: %s", err.Error())
	}
	for _, aInfo := range accounts {
		accountId := aInfo.GetAccountId64()
		r.Accounts[accountId] = &AWSAccount{
			Alias:        aInfo.AccountName, // AWS SSO calls it `AccountName`
			EmailAddress: aInfo.EmailAddress,
			Tags:         map[string]string{},
			Roles:        map[string]*AWSRole{},
		}

		roles, err := as.GetRoles(aInfo)
		if err != nil {
			return &r, fmt.Errorf("Unable to get AWS SSO roles: %s", err.Error())
		}
		for _, role := range roles {
			r.Accounts[accountId].Roles[role.RoleName] = &AWSRole{
				Arn: utils.MakeRoleARN(accountId, role.RoleName),
				Tags: map[string]string{
					"AccountID":    aInfo.AccountId,
					"AccountAlias": aInfo.AccountName, // AWS SSO calls it `AccountName`
					"Email":        aInfo.EmailAddress,
					"Role":         role.RoleName,
				},
			}
			// need to copy over the Expires & History fields from our current cache
			if _, ok := c.Roles.Accounts[accountId]; ok {
				if _, ok := c.Roles.Accounts[accountId].Roles[role.RoleName]; ok {
					if expires := c.Roles.Accounts[accountId].Roles[role.RoleName].Expires; expires > 0 {
						r.Accounts[accountId].Roles[role.RoleName].Expires = expires
					}
					if v, ok := c.Roles.Accounts[accountId].Roles[role.RoleName].Tags["History"]; ok {
						r.Accounts[accountId].Roles[role.RoleName].Tags["History"] = v
					}
				}
			}
		}
	}

	// The load all the Config file stuff.  Normally this is just adding markup, but
	// for accounts &roles that are not in SSO, we may be creating them as well!
	for accountId, account := range config.Accounts {
		if _, ok := r.Accounts[accountId]; !ok {
			r.Accounts[accountId] = &AWSAccount{
				Tags:  map[string]string{},
				Roles: map[string]*AWSRole{},
			}
		}
		r.Accounts[accountId].DefaultRegion = account.DefaultRegion
		r.Accounts[accountId].Name = account.Name

		// set our account tags
		for k, v := range config.Accounts[accountId].Tags {
			r.Accounts[accountId].Tags[k] = v
		}

		// set the AWS SSO tags for all the SSO roles
		for roleName := range r.Accounts[accountId].Roles {
			aId, _ := utils.AccountIdToString(accountId)
			r.Accounts[accountId].Roles[roleName].Tags["AccountID"] = aId
			r.Accounts[accountId].Roles[roleName].Tags["AccountAlias"] = r.Accounts[accountId].Alias
			r.Accounts[accountId].Roles[roleName].Tags["Email"] = r.Accounts[accountId].EmailAddress
			r.Accounts[accountId].Roles[roleName].Tags["Role"] = roleName
			if r.Accounts[accountId].Name != "" {
				r.Accounts[accountId].Roles[roleName].Tags["AccountName"] = r.Accounts[accountId].Name
			}
			if r.Accounts[accountId].Roles[roleName].DefaultRegion != "" {
				r.Accounts[accountId].Roles[roleName].Tags["DefaultRegion"] = r.Accounts[accountId].Roles[roleName].DefaultRegion
			}
		}

		// set the tags from the config file
		for roleName, role := range config.Accounts[accountId].Roles {
			if _, ok := r.Accounts[accountId].Roles[roleName]; !ok {
				r.Accounts[accountId].Roles[roleName] = &AWSRole{
					Tags: map[string]string{},
				}
			}
			r.Accounts[accountId].Roles[roleName].Arn = utils.MakeRoleARN(accountId, roleName)
			r.Accounts[accountId].Roles[roleName].Profile = role.Profile
			r.Accounts[accountId].Roles[roleName].DefaultRegion = r.Accounts[accountId].DefaultRegion
			r.Accounts[accountId].Roles[roleName].Via = role.Via
			if role.DefaultRegion != "" {
				r.Accounts[accountId].Roles[roleName].DefaultRegion = role.DefaultRegion
			}
			// Copy the account tags to the role
			for k, v := range config.Accounts[accountId].Tags {
				r.Accounts[accountId].Roles[roleName].Tags[k] = v
			}
			// Insert role specific tags (possible overwrite of account level)
			for k, v := range role.Tags {
				r.Accounts[accountId].Roles[roleName].Tags[k] = v
			}
		}
	}

	return &r, nil
}

// returns all tags, but with with spaces replaced with underscores
func (c *Cache) GetAllTagsSelect() *TagsList {
	tags := c.Roles.GetAllTags()
	fixedTags := NewTagsList()
	for k, values := range *tags {
		key := strings.ReplaceAll(k, " ", "_")
		for _, v := range values {
			if key == "History" {
				v = reformatHistory(v)
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
	fList := c.Roles.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			key := strings.ReplaceAll(k, " ", "_")
			if key == "History" {
				v = reformatHistory(v)
			}
			value := strings.ReplaceAll(v, " ", "_")
			ret[role.Arn][key] = value
		}
	}
	return &ret
}

// AccountIds returns all the configured AWS SSO AccountIds
func (r *Roles) AccountIds() []int64 {
	ret := []int64{}
	for id := range r.Accounts {
		ret = append(ret, id)
	}
	return ret
}

// AllRoles returns all the Roles as a flat list
func (r *Roles) GetAllRoles() []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, id := range r.AccountIds() {
		for roleName := range r.Accounts[id].Roles {
			flat, _ := r.GetRole(id, roleName)
			ret = append(ret, flat)
		}
	}
	return ret
}

// GetAccountRoles returns all the roles for a given account
func (r *Roles) GetAccountRoles(accountId int64) map[string]*AWSRoleFlat {
	ret := map[string]*AWSRoleFlat{}
	account := r.Accounts[accountId]
	if account == nil {
		return ret
	}
	for roleName := range account.Roles {
		flat, _ := r.GetRole(accountId, roleName)
		ret[roleName] = flat
	}
	return ret
}

// GetAllTags returns all the unique key/tag pairs for every role
func (r *Roles) GetAllTags() *TagsList {
	ret := TagsList{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		for k, v := range role.Tags {
			ret.Add(k, v)
		}
	}
	return &ret
}

// GetRoleTags returns all the tags for each role
func (r *Roles) GetRoleTags() *RoleTags {
	ret := RoleTags{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			ret[role.Arn][k] = v
		}
	}
	return &ret
}

// Role returns the specified role as an AWSRoleFlat
func (r *Roles) GetRole(accountId int64, roleName string) (*AWSRoleFlat, error) {
	account, ok := r.Accounts[accountId]
	if !ok {
		return &AWSRoleFlat{}, fmt.Errorf("Invalid AWS AccountID: %d", accountId)
	}
	for thisRoleName, role := range account.Roles {
		if thisRoleName == roleName {
			flat := AWSRoleFlat{
				AccountId:     accountId,
				AccountName:   account.Name,
				AccountAlias:  account.Alias,
				EmailAddress:  account.EmailAddress,
				Expires:       role.Expires,
				Arn:           role.Arn,
				RoleName:      roleName,
				Profile:       role.Profile,
				DefaultRegion: r.DefaultRegion,
				SSORegion:     r.SSORegion,
				StartUrl:      r.StartUrl,
				Tags:          map[string]string{},
				Via:           role.Via,
			}

			// copy over account tags
			for k, v := range account.Tags {
				flat.Tags[k] = v
			}
			// override account values with more specific role values
			if account.DefaultRegion != "" {
				flat.DefaultRegion = account.DefaultRegion
			}
			if role.DefaultRegion != "" {
				flat.DefaultRegion = role.DefaultRegion
			}
			// Automatic tags
			flat.Tags["AccountID"], _ = utils.AccountIdToString(accountId)
			flat.Tags["Email"] = account.EmailAddress

			if account.Alias != "" {
				flat.Tags["AccountAlias"] = account.Alias
			}

			if flat.AccountName != "" {
				flat.Tags["AccountName"] = flat.AccountName
			}

			if role.Profile != "" {
				flat.Tags["Profile"] = role.Profile
			}

			if role.Via != "" {
				flat.Tags["Via"] = role.Via
			}

			// finally override role specific tags
			for k, v := range role.Tags {
				flat.Tags[k] = v
			}
			return &flat, nil
		}
	}
	return &AWSRoleFlat{}, fmt.Errorf("Unable to find role %d:%s", accountId, roleName)
}

// GetRoleChain figures out the AssumeRole chain required to assume the given role
func (r *Roles) GetRoleChain(accountId int64, roleName string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}

	f, err := r.GetRole(accountId, roleName)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role: %s", utils.MakeRoleARN(accountId, roleName))
	}
	ret = append(ret, f)
	for f.Via != "" {
		aId, rName, err := utils.ParseRoleARN(f.Via)
		if err != nil {
			log.WithError(err).Fatalf("Unable to parse '%s'", f.Via)
		}
		f, err = r.GetRole(aId, rName)
		if err != nil {
			log.WithError(err).Fatalf("Unable to get role: %s", utils.MakeRoleARN(aId, rName))
		}
		ret = append([]*AWSRoleFlat{f}, ret...) // prepend
	}

	return ret
}

// MatchingRoles returns all the roles matching the given tags
func (r *Roles) MatchingRoles(tags map[string]string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, role := range r.GetAllRoles() {
		matches := true
		for k, v := range tags {
			if roleVal, ok := role.Tags[k]; ok {
				if roleVal != v {
					matches = false
				}
			} else {
				matches = false
			}
			if !matches {
				break
			}
		}
		if matches {
			ret = append(ret, role)
		}
	}
	return ret
}

// MatchingRolesWithTagKey returns the roles that have the tag key
func (r *Roles) MatchingRolesWithTagKey(key string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, role := range r.GetAllRoles() {
		for k := range role.Tags {
			if k == key {
				ret = append(ret, role)
				break
			}
		}
	}
	return ret
}

// IsExpired returns if this role has expired or has no creds available
func (r *AWSRoleFlat) IsExpired() bool {
	if r.Expires == 0 {
		return true
	}
	d := time.Until(time.Unix(r.Expires, 0))
	return d <= 0
}

// ExpiresIn returns how long until this role expires as a string
func (r *AWSRoleFlat) ExpiresIn() (string, error) {
	return utils.TimeRemain(r.Expires, false)
}
