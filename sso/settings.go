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
	"os"
	"strconv"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	//	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

const (
	AWS_SESSION_EXPIRATION_FORMAT = "2006-01-02 15:04:05 -0700 MST"
	CACHE_TTL                     = 60 * 60 * 24 // 1 day in seconds
)

type Settings struct {
	configFile        string                // name of this file
	cacheFile         string                // name of cache file; always passed in via CLI args
	Cache             *Cache                // our cache data
	SSO               map[string]*SSOConfig `koanf:"SSOConfig" yaml:"SSOConfig,omitempty"`
	DefaultSSO        string                `koanf:"DefaultSSO" yaml:"DefaultSSO,omitempty"`   // specify default SSO by key
	SecureStore       string                `koanf:"SecureStore" yaml:"SecureStore,omitempty"` // json or keyring
	JsonStore         string                `koanf:"JsonStore" yaml:"JsonStore,omitempty"`
	UrlAction         string                `koanf:"UrlAction" yaml:"UrlAction,omitempty"`
	Browser           string                `koanf:"Browser" yaml:"Browser,omitempty"`
	ProfileFormat     string                `koanf:"ProfileFormat" yaml:"ProfileFormat,omitempty"`
	AccountPrimaryTag []string              `koanf:"AccountPrimaryTag" yaml:"AccountPrimaryTag"`
	PromptColors      PromptColors          `koanf:"PromptColors" yaml:"PromptColors,omitempty"` // go-prompt colors
	LogLevel          string                `koanf:"LogLevel" yaml:"LogLevel,omitempty"`
	LogLines          bool                  `koanf:"LogLines" yaml:"LogLines,omitempty"`
	ssoName           string                // SSO name passed in via CLI
}

type SSOConfig struct {
	settings      *Settings             // pointer back up
	SSORegion     string                `koanf:"SSORegion" yaml:"SSORegion"`
	StartUrl      string                `koanf:"StartUrl" yaml:"StartUrl"`
	Accounts      map[int64]*SSOAccount `koanf:"Accounts" yaml:"Accounts,omitempty"`
	DefaultRegion string                `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
}

type SSOAccount struct {
	config        *SSOConfig          // pointer back up
	Name          string              `koanf:"Name" yaml:"Name,omitempty"` // Admin configured Account Name
	Tags          map[string]string   `koanf:"Tags" yaml:"Tags,omitempty" `
	Roles         map[string]*SSORole `koanf:"Roles" yaml:"Roles,omitempty"`
	DefaultRegion string              `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
}

type SSORole struct {
	account       *SSOAccount       // pointer back up
	ARN           string            `koanf:"ARN" yaml:"ARN"`
	Profile       string            `koanf:"Profile" yaml:"Profile,omitempty"`
	Tags          map[string]string `koanf:"Tags" yaml:"Tags,omitempty"`
	DefaultRegion string            `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	Via           string            `koanf:"Via" yaml:"Via,omitempty"`
}

// Our Cachefile.  Sub-structs defined in sso/cache.go
type Cache struct {
	settings        *Settings // pointer back up
	CreatedAt       int64     `json:"CreatedAt"`       // this cache.json
	ConfigCreatedAt int64     `json:"ConfigCreatedAt"` // track config.yaml
	History         []string  `json:"History,omitempty"`
	Roles           *Roles    `json:"Roles,omitempty"`
}

var DEFAULT_ACCOUNT_PRIMARY_TAGS []string = []string{
	"AccountName",
	"AccountAlias",
	"Email",
}

type OverrideSettings struct {
	Browser    string
	DefaultSSO string
	LogLevel   string
	LogLines   bool
	UrlAction  string
}

// Loads our settings from config, cache and CLI args
func LoadSettings(configFile, cacheFile string, defaults map[string]interface{}, override OverrideSettings) (*Settings, error) {
	konf := koanf.New(".")
	s := &Settings{
		configFile: configFile,
		cacheFile:  cacheFile,
	}

	// default values.  Can be overridden using:
	// https://pkg.go.dev/github.com/c-bata/go-prompt?utm_source=godoc#Color
	konf.Load(confmap.Provider(defaults, "."), nil)

	if err := konf.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		return s, fmt.Errorf("Unable to open config file %s: %s", configFile, err.Error())
	}

	if err := konf.Unmarshal("", s); err != nil {
		return s, fmt.Errorf("Unable to process config file: %s", err.Error())
	}

	if len(s.AccountPrimaryTag) == 0 {
		s.AccountPrimaryTag = append(s.AccountPrimaryTag, DEFAULT_ACCOUNT_PRIMARY_TAGS...)
	}

	// Setup Logging
	if override.LogLevel != "" {
		s.LogLevel = override.LogLevel
	}
	switch s.LogLevel {
	case "trace":
		log.SetLevel(log.TraceLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if override.LogLines {
		s.LogLines = true
	}
	if s.LogLines {
		log.SetReportCaller(true)
	}

	// Other overrides from CLI
	if override.Browser != "" {
		s.Browser = override.Browser
	}
	if override.DefaultSSO != "" {
		s.DefaultSSO = override.DefaultSSO
	}
	if override.UrlAction != "" {
		s.UrlAction = override.UrlAction
	}

	// Select our SSO Provider
	if len(s.SSO) == 0 {
		return s, fmt.Errorf("No AWS SSO providers have been configured.")
	} else if len(s.SSO) == 1 {
		// If we have only one SSO configured, always use that
		for name, _ := range s.SSO {
			s.DefaultSSO = name
		}
	} else if _, ok := s.SSO[s.DefaultSSO]; !ok {
		// more than one provider? use that
		names := []string{}
		for sso, _ := range s.SSO {
			names = append(names, sso)
		}
		return s, fmt.Errorf("Invalid SSO name '%s'. Valid options: %s", s.DefaultSSO,
			strings.Join(names, ", "))
	} else {
		// couldn't find a valid provider
		return s, fmt.Errorf("Please specify --sso, $AWS_SSO or set DefaultSSO in the config file")
	}

	s.SSO[s.DefaultSSO].Refresh(s)

	// load the cache
	var err error
	if s.Cache, err = s.OpenCache(); err != nil {
		return s, err
	}

	return s, nil
}

func (s *Settings) ConfigFile() string {
	return s.configFile
}

func (s *Settings) CreatedAt() int64 {
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

func (s *Settings) OpenCache() (*Cache, error) {
	cache := Cache{
		settings:        s,
		CreatedAt:       0,
		ConfigCreatedAt: 0,
		History:         []string{},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{},
		},
	}
	if s.cacheFile != "" {
		cacheBytes, err := ioutil.ReadFile(s.cacheFile)
		if err != nil {
			log.WithError(err).Errorf("Unable to open CacheStore: %s", s.cacheFile)
			return &cache, nil // return empty struct
		}
		json.Unmarshal(cacheBytes, &cache)
	}
	return &cache, nil
}

// GetSelectedSSO returns a valid SSOConfig based on user intput, configured
// value or our hardcoded 'Default' if it exists.
func (s *Settings) GetSelectedSSO(name string) (*SSOConfig, error) {
	if c, ok := s.SSO[name]; ok {
		return c, nil
	}

	if c, ok := s.SSO[s.DefaultSSO]; ok {
		return c, nil
	}

	if c, ok := s.SSO["Default"]; ok {
		return c, nil
	}
	return &SSOConfig{}, fmt.Errorf("No available SSOConfig Provider")
}

// Refresh should be called any time you load the SSOConfig into memory or add a role
// to update the Role -> Account references
func (c *SSOConfig) Refresh(s *Settings) {
	for _, a := range c.Accounts {
		for _, r := range a.Roles {
			r.SetParentAccount(a)
		}
	}
	c.settings = s
}

// ConfigFile returns the path to the config file
func (c *SSOConfig) ConfigFile() string {
	return c.settings.ConfigFile()
}

// CreatedAt returns the Unix epoch seconds that this config file was created at
func (c *SSOConfig) CreatedAt() int64 {
	return c.settings.CreatedAt()
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

func (r *SSORole) SetParentAccount(a *SSOAccount) {
	r.account = a
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
