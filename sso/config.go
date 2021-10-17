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
	"os"
	"strconv"
	"strings"

	//	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type AWSProfile struct {
	Alias     string `koanf:"Alias" yaml:"Alias,omitempty"`         // Friendly name
	Role      string `koanf:"Role" yaml:"Role,omitempty"`           // AWS Role Name
	Region    string `koanf:"Region" yaml:"Region,omitempty"`       // AWS Default Region
	AccountId string `koanf:"AccountId" yaml:"AccountId,omitempty"` // AWS AccountId
}

type ConfigFile struct {
	SSO               map[string]*SSOConfig `koanf:"SSOConfig" yaml:"SSOConfig,omitempty"`
	DefaultSSO        string                `koanf:"DefaultSSO" yaml:"DefaultSSO,omitempty"`   // specify default SSO by key
	SecureStore       string                `koanf:"SecureStore" yaml:"SecureStore,omitempty"` // json or keyring
	CacheStore        string                `koanf:"CacheStore" yaml:"CacheStore,omitempty"`   // insecure json cache
	JsonStore         string                `koanf:"JsonStore" yaml:"JsonStore,omitempty"`
	PrintUrl          bool                  `koanf:"PrintUrl" yaml:"PrintUrl,omitempty"`
	Browser           string                `koanf:"Browser" yaml:"Browser,omitempty"`
	ProfileFormat     string                `koanf:"ProfileFormat" yaml:"ProfileFormat,omitempty"`
	AccountPrimaryTag []string              `koanf:"AccountPrimaryTag" yaml:"AccountPrimaryTag"`
}

type SSOConfig struct {
	SSORegion     string                `koanf:"SSORegion" yaml:"SSORegion"`
	StartUrl      string                `koanf:"StartUrl" yaml:"StartUrl"`
	Accounts      map[int64]*SSOAccount `koanf:"Accounts" yaml:"Accounts,omitempty"`
	DefaultRegion string                `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	configFile    string                // populated by Refresh()
}

type SSOAccount struct {
	Name          string              `koanf:"Name" yaml:"Name,omitempty"` // Admin configured Account Name
	Tags          map[string]string   `koanf:"Tags" yaml:"Tags,omitempty" `
	Roles         map[string]*SSORole `koanf:"Roles" yaml:"Roles,omitempty"`
	DefaultRegion string              `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
}

type SSORole struct {
	Account       *SSOAccount
	ARN           string            `koanf:"ARN" yaml:"ARN"`
	Profile       string            `koanf:"Profile" yaml:"Profile,omitempty"`
	Tags          map[string]string `koanf:"Tags" yaml:"Tags,omitempty"`
	DefaultRegion string            `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	Via           string            `koanf:"Via" yaml:"Via,omitempty"`
}

// DefaultSSO returns the Default SSO or failing that the first one it finds
func (cf *ConfigFile) GetDefaultSSO() *SSOConfig {
	if s, ok := cf.SSO[cf.DefaultSSO]; ok {
		return s
	}

	if s, ok := cf.SSO["Default"]; ok {
		return s
	}
	var s *SSOConfig
	for _, v := range cf.SSO {
		s = v
	}
	return s
}

// Refresh should be called any time you load the SSOConfig into memory or add a role
// to update the Role -> Account references
func (s *SSOConfig) Refresh(configFile string) {
	for _, a := range s.Accounts {
		for _, r := range a.Roles {
			r.Account = a
		}
	}
	// update our createdAt.  Sadly we need to put it here and not in ConfigFile
	s.configFile = configFile
}

// ConfigFile returns the path to the config file
func (s *SSOConfig) ConfigFile() string {
	return s.configFile
}

// CreatedAt returns the Unix epoch seconds that this config file was created at
func (s *SSOConfig) CreatedAt() int64 {
	f, err := os.Open(s.configFile)
	if err != nil {
		log.WithError(err).Fatalf("Unable to open %s", s.configFile)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.WithError(err).Fatalf("Unable to Stat() %s", s.configFile)
	}
	return info.ModTime().Unix()
}

// HasRole returns true/false if the given Account has the provided arn
func (a *SSOAccount) HasRole(arn string) bool {
	hasRole := false
	for _, role := range a.Roles {
		if role.ARN == arn {
			hasRole = true
			break
		}
	}
	return hasRole
}

// GetRoles returns a list of all the roles for this SSOConfig
func (s *SSOConfig) GetRoles() []*SSORole {
	roles := []*SSORole{}
	for _, a := range s.Accounts {
		for _, r := range a.Roles {
			roles = append(roles, r)
		}
	}
	return roles
}

// GetAllTags returns all of the user defined tags and calculated tags for this account
func (a *SSOAccount) GetAllTags(id int64) map[string]string {
	accountName := "*Unknown*"

	if a.Name != "" {
		accountName = strings.ReplaceAll(a.Name, " ", "_")
	}
	tags := map[string]string{
		"AccountName": accountName,
	}
	if id > 0 {
		accountId := strconv.FormatInt(id, 10)
		tags["AccountId"] = accountId
	}
	if a.DefaultRegion != "" {
		tags["DefaultRegion"] = a.DefaultRegion
	}
	for k, v := range a.Tags {
		tags[k] = v
	}
	return tags
}

// GetAllTags returns all of the user defined and calculated tags for this role
func (r *SSORole) GetAllTags() map[string]string {
	tags := map[string]string{}
	// First pull in the account tags
	for k, v := range r.Account.GetAllTags(r.GetAccountId64()) {
		tags[k] = v
	}

	// Then override/add any specific tags
	tags["RoleName"] = r.GetRoleName()
	tags["AccountId"] = r.GetAccountId()

	if r.DefaultRegion != "" {
		tags["DefaultRegion"] = r.DefaultRegion
	}
	for k, v := range r.Tags {
		tags[k] = v
	}

	return tags
}

// GetRoleName returns the role name portion of the ARN
func (r *SSORole) GetRoleName() string {
	s := strings.Split(r.ARN, "/")
	return s[1]
}

// GetAccountId returns the accountId portion of the ARN or empty string on error
func (r *SSORole) GetAccountId() string {
	s := strings.Split(r.ARN, ":")
	if len(s) < 4 {
		log.Errorf("Role.ARN is missing the account field: '%v'\n%v", r.ARN, *r)
		return ""
	}
	return s[3]
}

// GetAccountId64 returns the accountId portion of the ARN
func (r *SSORole) GetAccountId64() int64 {
	i, err := strconv.ParseInt(r.GetAccountId(), 10, 64)
	if err != nil {
		log.WithError(err).Panicf("Unable to decode account id for %s", r.ARN)
	}
	return i
}

// returns all of the available account & role tags for our SSO Provider
func (s *SSOConfig) GetAllTags() *TagsList {
	tags := NewTagsList()
	for _, accountInfo := range s.Accounts {
		/*
			if accountInfo.Tags != nil {
				for k, v := range accountInfo.GetAllTags(account) {
					tags.Add(k, v)
				}
			}
		*/
		for _, roleInfo := range accountInfo.Roles {
			for k, v := range roleInfo.GetAllTags() {
				tags.Add(k, v)
			}
		}
	}
	return tags
}

// GetRoleMatches finds all the roles which match all of the given tags
func (s *SSOConfig) GetRoleMatches(tags map[string]string) []*SSORole {
	match := []*SSORole{}
	for _, role := range s.GetRoles() {
		isMatch := true
		roleTags := role.GetAllTags()
		for tk, tv := range tags {
			if roleTags[tk] != tv {
				isMatch = false
				break
			}
		}
		if isMatch {
			match = append(match, role)
		}
	}
	return match
}
