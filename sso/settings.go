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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// "github.com/davecgh/go-spew/spew"
	goyaml "github.com/goccy/go-yaml"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
)

const (
	AWS_SESSION_EXPIRATION_FORMAT = "2006-01-02 15:04:05 -0700 MST"
	CACHE_TTL                     = 60 * 60 * 24 // 1 day in seconds
)

type Settings struct {
	configFile        string                // name of this file
	cacheFile         string                // name of cache file; always passed in via CLI args
	Cache             *Cache                `yaml:"-"` // our cache data
	SSO               map[string]*SSOConfig `koanf:"SSOConfig" yaml:"SSOConfig,omitempty"`
	DefaultSSO        string                `koanf:"DefaultSSO" yaml:"DefaultSSO,omitempty"`   // specify default SSO by key
	SecureStore       string                `koanf:"SecureStore" yaml:"SecureStore,omitempty"` // json or keyring
	DefaultRegion     string                `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	JsonStore         string                `koanf:"JsonStore" yaml:"JsonStore,omitempty"`
	UrlAction         string                `koanf:"UrlAction" yaml:"UrlAction,omitempty"`
	Browser           string                `koanf:"Browser" yaml:"Browser,omitempty"`
	ProfileFormat     string                `koanf:"ProfileFormat" yaml:"ProfileFormat,omitempty"`
	AccountPrimaryTag []string              `koanf:"AccountPrimaryTag" yaml:"AccountPrimaryTag,omitempty"`
	PromptColors      PromptColors          `koanf:"PromptColors" yaml:"PromptColors,omitempty"` // go-prompt colors
	LogLevel          string                `koanf:"LogLevel" yaml:"LogLevel,omitempty"`
	LogLines          bool                  `koanf:"LogLines" yaml:"LogLines,omitempty"`
	HistoryLimit      int                   `koanf:"HistoryLimit" yaml:"HistoryLimit,omitempty"`
	ListFields        []string              `koanf:"ListFields" yaml:"ListFields,omitempty"`
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
	ARN           string            `yaml:"ARN"`
	Profile       string            `koanf:"Profile" yaml:"Profile,omitempty"`
	Tags          map[string]string `koanf:"Tags" yaml:"Tags,omitempty"`
	DefaultRegion string            `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	Via           string            `koanf:"Via" yaml:"Via,omitempty"`
}

// GetDefaultRegion returns the user defined AWS_DEFAULT_REGION for the specified role
func (s *Settings) GetDefaultRegion(accountId int64, roleName string) string {
	roleFlat, err := s.Cache.Roles.GetRole(accountId, roleName)
	if err != nil {
		if s.SSO[s.DefaultSSO].DefaultRegion != "" {
			return s.SSO[s.DefaultSSO].DefaultRegion
		} else {
			return s.DefaultRegion
		}
	}
	if roleFlat.DefaultRegion != "" {
		return roleFlat.DefaultRegion
	}
	return s.DefaultRegion
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
	if err := konf.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return s, fmt.Errorf("Unable to load default settings: %s", err.Error())
	}

	if err := konf.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		return s, fmt.Errorf("Unable to open config file %s: %s", configFile, err.Error())
	}

	if err := konf.Unmarshal("", s); err != nil {
		return s, fmt.Errorf("Unable to process config file: %s", err.Error())
	}

	if len(s.AccountPrimaryTag) == 0 {
		s.AccountPrimaryTag = append(s.AccountPrimaryTag, DEFAULT_ACCOUNT_PRIMARY_TAGS...)
	}

	s.setOverrides(override)

	// Select our SSO Provider
	if len(s.SSO) == 0 {
		return s, fmt.Errorf("No AWS SSO providers have been configured.")
	} else if len(s.SSO) == 1 {
		// If we have only one SSO configured, always use that
		for name := range s.SSO {
			s.DefaultSSO = name
		}
	} else if _, ok := s.SSO[s.DefaultSSO]; !ok {
		// more than one provider? use that
		names := []string{}
		for sso := range s.SSO {
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
	if s.Cache, err = OpenCache(s.cacheFile, s); err != nil {
		log.Warnf("%s", err.Error())
	}

	return s, nil
}

// Save overwrites the current config file with our settings (not recommended)
func (s *Settings) Save(configFile string, overwrite bool) error {
	if _, err := os.Stat(configFile); !errors.Is(err, os.ErrNotExist) && !overwrite {
		return fmt.Errorf("Refusing to overwrite %s", configFile)
	}

	data, err := goyaml.Marshal(s)
	if err != nil {
		return err
	}

	configDir := utils.GetHomePath(filepath.Dir(configFile))
	configFile = filepath.Join(configDir, filepath.Base(configFile))
	if err = utils.EnsureDirExists(configFile); err != nil {
		return err
	}

	// need to make directory if not exist
	return ioutil.WriteFile(configFile, data, 0600)
}

// configure our settings using the overrides
func (s *Settings) setOverrides(override OverrideSettings) {
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

// GetSelectedSSO returns a valid SSOConfig based on user intput, configured
// value or our hardcoded 'Default' if it exists and name is empty String
func (s *Settings) GetSelectedSSO(name string) (*SSOConfig, error) {
	if c, ok := s.SSO[name]; ok {
		return c, nil
	}

	if c, ok := s.SSO[s.DefaultSSO]; ok && s.DefaultSSO != "Default" {
		return c, nil
	}

	if c, ok := s.SSO["Default"]; ok && name == "" {
		return c, nil
	}
	return &SSOConfig{}, fmt.Errorf("No available SSOConfig Provider")
}

// Refresh should be called any time you load the SSOConfig into memory or add a role
// to update the Role -> Account references
func (c *SSOConfig) Refresh(s *Settings) {
	for accountId, a := range c.Accounts {
		a.SetParentConfig(c)
		for roleName, r := range a.Roles {
			r.SetParentAccount(a)
			r.ARN = utils.MakeRoleARN(accountId, roleName)
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
