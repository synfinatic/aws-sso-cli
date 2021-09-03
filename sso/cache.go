package sso

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
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/gotable"
)

const (
	AWS_SESSION_EXPIRATION_FORMAT = "2006-01-02 15:04:05 -0700 MST"
	CACHE_TTL                     = 60 * 60 * 24 // 1 day in seconds
)

// Our Cachefile
type Cache struct {
	filename  string
	CreatedAt int64    `json:"CreatedAt"`
	History   []string `json:"History,omitempty"`
	Roles     *Roles   `json:"Roles,omitempty"`
}

func OpenCache(filename string) (*Cache, error) {
	cache := Cache{
		filename: filename,
	}
	cacheBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return &cache, err
	}
	json.Unmarshal(cacheBytes, &cache)
	return &cache, nil
}

// Expired returns if our Roles cache data is too old
func (c *Cache) Expired() bool {
	if c.CreatedAt+CACHE_TTL < time.Now().Unix() {
		return true
	}
	return false
}

// Save saves our cache to the current file
func (c *Cache) Save() error {
	jbytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	err = ensureDirExists(c.filename)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.filename, jbytes, 0600)
}

// SaveToFile saves our cache to the specified file
func (c *Cache) SaveToFile(filename string) error {
	c.filename = filename
	return c.Save()
}

// adds a role to the History list up to the max number of entries
func (c *Cache) AddHistory(item string, max int) {
	c.History = append([]string{item}, c.History...) // push on top
	for len(c.History) > max {
		// remove the oldest entry
		c.History = c.History[:len(c.History)-1]
	}
}

// Refresh updates our cached Roles based on AWS SSO & our Config
// but does not save this data!
func (c *Cache) Refresh(sso *AWSSSO, config *SSOConfig) error {
	r, err := NewRoles(sso, c.Roles.SSOName, config)
	if err != nil {
		return err
	}
	c.Roles = r
	c.CreatedAt = time.Now().Unix()
	return nil
}

// main struct holding all our Roles discovered via AWS SSO and
// via the config.yaml
type Roles struct {
	// sso           *AWSSSO
	SSOName       string                `json:"SSOName"`
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
	Expires       string            `json:"Expires,omitempty"` // 2006-01-02 15:04:05 -0700 MST
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
	Expires       string            `json:"Expires" header:"Expires"`
	Arn           string            `json:"Arn" header:"ARN"`
	RoleName      string            `json:"RoleName" header:"Role"`
	Profile       string            `json:"Profile" header:"Profile"`
	DefaultRegion string            `json:"DefaultRegion" header:"DefaultRegion"`
	SSORegion     string            `json:"SSORegion" header:"SSORegion"`
	StartUrl      string            `json:"StartUrl" header:"StartUrl"`
	Tags          map[string]string `json:"Tags"` // not supported by GenerateTable
	Via           string            `json:"Via" header:"Via"`
	SelectTags    map[string]string // only used for
}

func (f AWSRoleFlat) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(f)
	return gotable.GetHeaderTag(v, fieldName)
}

// Merges the AWS SSO and our Config file to create our Roles struct
func NewRoles(as *AWSSSO, ssoName string, config *SSOConfig) (*Roles, error) {
	r := Roles{
		// sso:           as,
		SSOName:       ssoName,
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
			Alias:        aInfo.AccountName,
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
				Arn:  MakeRoleARN(accountId, role.RoleName),
				Tags: map[string]string{},
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

		// set the tags for all the SSO roles
		for roleName, _ := range r.Accounts[accountId].Roles {
			aId := strconv.FormatInt(accountId, 10)
			r.Accounts[accountId].Roles[roleName].Tags["AccountID"] = aId
			r.Accounts[accountId].Roles[roleName].Tags["AccountName"] = r.Accounts[accountId].Name
			r.Accounts[accountId].Roles[roleName].Tags["AccountAlias"] = r.Accounts[accountId].Alias
			r.Accounts[accountId].Roles[roleName].Tags["Email"] = r.Accounts[accountId].EmailAddress
			r.Accounts[accountId].Roles[roleName].Tags["Role"] = roleName
			if r.Accounts[accountId].Roles[roleName].DefaultRegion != "" {
				r.Accounts[accountId].Roles[roleName].Tags["DefaultRegion"] = r.Accounts[accountId].Roles[roleName].DefaultRegion
			}
		}

		for roleName, role := range config.Accounts[accountId].Roles {
			if _, ok := r.Accounts[accountId].Roles[roleName]; !ok {
				r.Accounts[accountId].Roles[roleName] = &AWSRole{
					Tags: map[string]string{},
				}
			}
			r.Accounts[accountId].Roles[roleName].Arn = MakeRoleARN(accountId, roleName)
			r.Accounts[accountId].Roles[roleName].Profile = role.Profile
			r.Accounts[accountId].Roles[roleName].Via = role.Via
			r.Accounts[accountId].Roles[roleName].DefaultRegion = r.Accounts[accountId].DefaultRegion
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

// AccountIds returns all the configured AWS SSO AccountIds
func (r *Roles) AccountIds() []int64 {
	ret := []int64{}
	for id, _ := range r.Accounts {
		ret = append(ret, id)
	}
	return ret
}

// AllRoles returns all the Roles as a flat list
func (r *Roles) GetAllRoles() []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}
	for _, id := range r.AccountIds() {
		for roleName, _ := range r.Accounts[id].Roles {
			flat, _ := r.GetRole(id, roleName)
			ret = append(ret, flat)
		}
	}
	return ret
}

// AccountRoles returns all the roles for a given account
func (r *Roles) GetAccountRoles(accountId int64) map[string]*AWSRoleFlat {
	ret := map[string]*AWSRoleFlat{}
	account := r.Accounts[accountId]
	for roleName, _ := range account.Roles {
		flat, _ := r.GetRole(accountId, roleName)
		ret[roleName] = flat
	}
	return ret
}

// GetAllTags returns all the tags for every role
func (r *Roles) GetAllTags() *TagsList {
	ret := TagsList{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		for k, v := range role.Tags {
			if _, ok := ret[k]; !ok {
				ret[k] = []string{}
			}
			hasValue := false
			for _, val := range ret[k] {
				if val == v {
					hasValue = true
					break
				}
			}
			if !hasValue {
				ret[k] = append(ret[k], v)
			}
		}
	}
	return &ret
}

// GetRoleTags returns all the tags for each role
func (r *Roles) GetRoleTags() *RoleTags {
	ret := RoleTags{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = role.Tags
	}
	return &ret
}

// GetRoleTagsSelect returns all the tags for each role with all the spaces
// replaced with underscores
func (r *Roles) GetRoleTagsSelect() *RoleTags {
	ret := RoleTags{}
	fList := r.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			key := strings.ReplaceAll(k, " ", "_")
			value := strings.ReplaceAll(v, " ", "_")
			ret[role.Arn][key] = value
		}
	}
	return &ret
}

// Role returns the specified role as an AWSRoleFlat
func (r *Roles) GetRole(accountId int64, roleName string) (*AWSRoleFlat, error) {
	account := r.Accounts[accountId]
	for thisRoleName, role := range account.Roles {
		if thisRoleName == roleName {
			flat := &AWSRoleFlat{
				AccountId:     accountId,
				AccountName:   account.Name,
				AccountAlias:  account.Alias,
				EmailAddress:  account.EmailAddress,
				Expires:       role.Expires,
				Tags:          account.Tags,
				Arn:           role.Arn,
				RoleName:      roleName,
				Profile:       role.Profile,
				DefaultRegion: r.DefaultRegion,
				SSORegion:     r.SSORegion,
				StartUrl:      r.StartUrl,
				Via:           role.Via,
			}

			// override account values with more specific role values
			if account.DefaultRegion != "" {
				flat.DefaultRegion = account.DefaultRegion
			}
			if role.DefaultRegion != "" {
				flat.DefaultRegion = role.DefaultRegion
			}
			// Automatic tags
			flat.Tags["AccountID"] = strconv.FormatInt(accountId, 10)
			flat.Tags["Email"] = account.EmailAddress
			if role.Profile != "" {
				flat.Tags["Profile"] = role.Profile
			}

			// Account name is by default the alias, but can be manually overridden
			flat.Tags["AccountName"] = flat.AccountAlias
			if flat.AccountName != "" {
				flat.Tags["AccountName"] = flat.AccountName
			}

			// finally override role specific tags
			for k, v := range role.Tags {
				flat.Tags[k] = v
			}
			return flat, nil
		}
	}
	return &AWSRoleFlat{}, fmt.Errorf("Unable to find role %d:%s", accountId, roleName)
}

// GetRoleChain figures out the AssumeRole chain required to assume the given role
func (r *Roles) GetRoleChain(accountId int64, roleName string) []*AWSRoleFlat {
	ret := []*AWSRoleFlat{}

	f, err := r.GetRole(accountId, roleName)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role: %s", MakeRoleARN(accountId, roleName))
	}
	ret = append(ret, f)
	for f.Via != "" {
		aId, rName, err := GetRoleParts(f.Via)
		if err != nil {
			log.WithError(err).Fatalf("Unable to parse '%s'", f.Via)
		}
		f, err = r.GetRole(aId, rName)
		if err != nil {
			log.WithError(err).Fatalf("Unable to get role: %s", MakeRoleARN(aId, rName))
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

// IsExpired returns if this role has expired or has no creds available
func (r *AWSRoleFlat) IsExpired() bool {
	if r.Expires == "" {
		return true
	}
	expires, err := time.Parse(AWS_SESSION_EXPIRATION_FORMAT, r.Expires)
	if err != nil {
		log.WithError(err).Errorf("Unable to parse expires '%s'", r.Expires)
		return true
	}
	d := time.Until(expires)
	if d <= 0 {
		return true
	}
	return false
}

// ExpiresIn returns how long until this role expires as a string
func (r *AWSRoleFlat) ExpiresIn() (string, error) {
	if r.Expires == "" {
		return "Expired", nil
	}
	expires, err := time.Parse(AWS_SESSION_EXPIRATION_FORMAT, r.Expires)
	if err != nil {
		return "", fmt.Errorf("Unable to parse expires '%s': %s", r.Expires, err.Error())
	}
	d := time.Until(expires)
	if d <= 0 {
		return "Expired", nil
	}
	return fmt.Sprintf("%s", strings.Replace(d.Round(time.Minute).String(), "0s", "", 1)), nil
}
