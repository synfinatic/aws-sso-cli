package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/tags"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type SSOConfig struct {
	settings      *Settings              // pointer back up
	key           string                 // our key in Settings.SSO[]
	SSORegion     string                 `koanf:"SSORegion" yaml:"SSORegion"`
	StartUrl      string                 `koanf:"StartUrl" yaml:"StartUrl"`
	Accounts      map[string]*SSOAccount `koanf:"Accounts" yaml:"Accounts,omitempty"` // key must be a string to avoid parse errors!
	DefaultRegion string                 `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`

	// overrides for this SSO Instance
	AuthUrlAction url.Action `koanf:"AuthUrlAction" yaml:"AuthUrlAction,omitempty"`

	// passed to AWSSSO from our Settings
	MaxBackoff int `koanf:"-" yaml:"-"`
	MaxRetry   int `koanf:"-" yaml:"-"`
}

type SSOAccount struct {
	config        *SSOConfig          // pointer back up
	Name          string              `koanf:"Name" yaml:"Name,omitempty"` // Admin configured Account Name
	Tags          map[string]string   `koanf:"Tags" yaml:"Tags,omitempty" `
	Roles         map[string]*SSORole `koanf:"Roles" yaml:"Roles,omitempty"`
	DefaultRegion string              `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
}

type SSORole struct {
	account        *SSOAccount       // pointer back up
	ARN            string            `yaml:"ARN"`
	Profile        string            `koanf:"Profile" yaml:"Profile,omitempty"`
	Tags           map[string]string `koanf:"Tags" yaml:"Tags,omitempty"`
	DefaultRegion  string            `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	Via            string            `koanf:"Via" yaml:"Via,omitempty"`
	ExternalId     string            `koanf:"ExternalId" yaml:"ExternalId,omitempty"`
	SourceIdentity string            `koanf:"SourceIdentity" yaml:"SourceIdentity,omitempty"`
}

// Refresh should be called any time you load the SSOConfig into memory or add a role
// to update the Role -> Account references
func (c *SSOConfig) Refresh(s *Settings) {
	c.MaxBackoff = s.MaxBackoff
	c.MaxRetry = s.MaxRetry

	if c.AuthUrlAction == url.Undef {
		c.AuthUrlAction = s.UrlAction
	}

	for accountId, a := range c.Accounts {
		// normalize the accountId to a string representation of an integer
		aId, err := utils.AccountIdToInt64(accountId)
		if err != nil {
			log.Fatal("Unable to parse accountId", "accountId", accountId, "error", err.Error())
		}
		id, _ := utils.AccountIdToString(aId)
		if id != accountId {
			log.Debug("Updating accountId", "old", accountId, "new", id)
			c.Accounts[id] = a
			delete(c.Accounts, accountId)
		}

		if a == nil {
			c.Accounts[id] = &SSOAccount{}
			a = c.Accounts[id]
		}
		a.SetParentConfig(c)
		for roleName, r := range a.Roles {
			if r == nil {
				c.Accounts[id].Roles[roleName] = &SSORole{}
				r = a.Roles[roleName]
			} else {
				log.Debug("Refreshing role", "accountId", id, "roleName", roleName)
			}
			r.SetParentAccount(a)
			r.ARN = utils.MakeRoleARNs(id, roleName)
		}
	}
	c.settings = s
}

// CreatedAt returns the Unix epoch seconds that this config file was created at
func (c *SSOConfig) CreatedAt() int64 {
	return c.settings.CreatedAt()
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

// returns all of the available account & role tags for our SSO Provider
func (s *SSOConfig) GetAllTags() *tags.TagsList {
	tags := tags.NewTagsList()

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

// GetRole returns the matching role if it exists
func (s *SSOConfig) GetRole(accountId int64, role string) (*SSORole, error) {
	id, err := utils.AccountIdToString(accountId)
	if err != nil {
		return &SSORole{}, err
	}

	if a, ok := s.Accounts[id]; ok {
		if r, ok := a.Roles[role]; ok {
			return r, nil
		}
	}
	return &SSORole{}, fmt.Errorf("unable to find %s:%s", id, role)
}

// GetConfigHash generates a SHA256 to be used to see if there are
// any changes which require updating our cache
func (s *SSOConfig) GetConfigHash(profileFormat string) string {
	hash := sha256.New()
	hash.Write([]byte(profileFormat))
	b, _ := json.Marshal(s.Accounts)
	hash.Write(b)
	return hex.EncodeToString(hash.Sum(nil))
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
		accountId, _ := utils.AccountIdToString(id)
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

func (r *SSORole) SetParentAccount(a *SSOAccount) {
	r.account = a
}

func (a *SSOAccount) SetParentConfig(c *SSOConfig) {
	a.config = c
}

// GetAllTags returns all of the user defined and calculated tags for this role
func (r *SSORole) GetAllTags() map[string]string {
	tags := map[string]string{}
	// First pull in the account tags
	for k, v := range r.account.GetAllTags(r.GetAccountId64()) {
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
	a, err := utils.AccountIdToString(r.GetAccountId64())
	if err != nil {
		log.Error("Unable to parse AccountId", "error", err.Error(), "accountID", r.GetAccountId64())
		return ""
	}
	return a
}

// GetAccountId64 returns the accountId portion of the ARN
func (r *SSORole) GetAccountId64() int64 {
	a, _, err := utils.ParseRoleARN(r.ARN)
	if err != nil {
		log.Fatal("Unable to parse", "arn", r.ARN, "error", err.Error())
	}
	return a
}
