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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// "github.com/davecgh/go-spew/spew"
	goyaml "github.com/goccy/go-yaml"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

const (
	NIX_STORE_PREFIX = "/nix/store/"
)

type Settings struct {
	configFile                string                   // name of this file
	cacheFile                 string                   // name of cache file; always passed in via CLI args
	Cache                     *Cache                   `yaml:"-"` // our cache data
	SSO                       map[string]*SSOConfig    `koanf:"SSOConfig" yaml:"SSOConfig,omitempty"`
	AutoLogin                 bool                     `koanf:"AutoLogin" yaml:"AutoLogin,omitempty"`
	DefaultSSO                string                   `koanf:"DefaultSSO" yaml:"DefaultSSO,omitempty"`   // specify default SSO by key
	SecureStore               string                   `koanf:"SecureStore" yaml:"SecureStore,omitempty"` // json or keyring
	DefaultRegion             string                   `koanf:"DefaultRegion" yaml:"DefaultRegion,omitempty"`
	ConsoleDuration           int32                    `koanf:"ConsoleDuration" yaml:"ConsoleDuration,omitempty"`
	JsonStore                 string                   `koanf:"JsonStore" yaml:"JsonStore,omitempty"`
	CacheRefresh              int64                    `koanf:"CacheRefresh" yaml:"CacheRefresh,omitempty"`
	Threads                   int                      `koanf:"Threads" yaml:"Threads,omitempty"`
	MaxBackoff                int                      `koanf:"MaxBackoff" yaml:"MaxBackoff,omitempty"`
	MaxRetry                  int                      `koanf:"MaxRetry" yaml:"MaxRetry,omitempty"`
	AutoConfigCheck           bool                     `koanf:"AutoConfigCheck" yaml:"AutoConfigCheck,omitempty"`
	FirefoxOpenUrlInContainer bool                     `koanf:"FirefoxOpenUrlInContainer" yaml:"FirefoxOpenUrlInContainer,omitempty"` // deprecated
	UrlAction                 url.Action               `koanf:"UrlAction" yaml:"UrlAction"`
	Browser                   string                   `koanf:"Browser" yaml:"Browser,omitempty"`
	ConfigUrlAction           string                   `koanf:"ConfigUrlAction" yaml:"ConfigUrlAction,omitempty"` // deprecated
	ConfigProfilesBinaryPath  string                   `koanf:"ConfigProfilesBinaryPath" yaml:"ConfigProfilesBinaryPath,omitempty"`
	ConfigProfilesUrlAction   url.ConfigProfilesAction `koanf:"ConfigProfilesUrlAction" yaml:"ConfigProfilesUrlAction,omitempty"`
	UrlExecCommand            []string                 `koanf:"UrlExecCommand" yaml:"UrlExecCommand,omitempty"` // string or list
	LogLevel                  string                   `koanf:"LogLevel" yaml:"LogLevel,omitempty"`
	LogLines                  bool                     `koanf:"LogLines" yaml:"LogLines,omitempty"`
	HistoryLimit              int64                    `koanf:"HistoryLimit" yaml:"HistoryLimit,omitempty"`
	HistoryMinutes            int64                    `koanf:"HistoryMinutes" yaml:"HistoryMinutes,omitempty"`
	ProfileFormat             string                   `koanf:"ProfileFormat" yaml:"ProfileFormat,omitempty"`
	AccountPrimaryTag         []string                 `koanf:"AccountPrimaryTag" yaml:"AccountPrimaryTag,omitempty"`
	FirstTag                  string                   `koanf:"FirstTag" yaml:"FirstTag,omitempty"`
	PromptColors              PromptColors             `koanf:"PromptColors" yaml:"PromptColors,omitempty"` // go-prompt colors
	ListFields                []string                 `koanf:"ListFields" yaml:"ListFields,omitempty"`
	ConfigVariables           map[string]interface{}   `koanf:"ConfigVariables" yaml:"ConfigVariables,omitempty"`
	EnvVarTags                []string                 `koanf:"EnvVarTags" yaml:"EnvVarTags,omitempty"`
	FullTextSearch            bool                     `koanf:"FullTextSearch" yaml:"FullTextSearch"`
}

// GetDefaultRegion scans the config settings file to pick the most local DefaultRegion from the tree
// for the given role
func (s *Settings) GetDefaultRegion(id int64, roleName string, noRegion bool) string {
	if noRegion {
		return ""
	}

	accountId, err := awsparse.AccountIdToString(id)
	if err != nil {
		log.Fatal("Unable to GetDefaultRegion()", "error", err.Error())
	}

	currentRegion := os.Getenv("AWS_DEFAULT_REGION")
	ssoManagedRegion := os.Getenv("AWS_SSO_DEFAULT_REGION")

	if len(currentRegion) > 0 && currentRegion != ssoManagedRegion {
		log.Debug("Will not override current AWS_DEFAULT_REGION", "region", currentRegion)
		return ""
	}

	role := s.DefaultRegion

	if c, ok := s.SSO[s.DefaultSSO]; ok {
		if c.DefaultRegion != "" {
			role = c.DefaultRegion
		}
		if a, ok := c.Accounts[accountId]; ok {
			if a.DefaultRegion != "" {
				role = a.DefaultRegion
			}
			if r, ok := a.Roles[roleName]; ok {
				if r.DefaultRegion != "" {
					role = r.DefaultRegion
				}
			}
		}
	}
	return role
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
	Threads    int
}

// Loads our settings from config, cache and CLI args
func LoadSettings(configFile, cacheFile string, defaults map[string]interface{}, override OverrideSettings) (*Settings, error) {
	var err error
	konf := koanf.New(".")
	s := &Settings{
		configFile: configFile,
		cacheFile:  cacheFile,
	}

	// default values.  Can be overridden using:
	// https://pkg.go.dev/github.com/c-bata/go-prompt?utm_source=godoc#Color
	if err = konf.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return s, fmt.Errorf("unable to load default settings: %s", err.Error())
	}

	if err = konf.Load(file.Provider(configFile), yaml.Parser()); err != nil {
		return s, fmt.Errorf("unable to open config file %s: %s", configFile, err.Error())
	}

	if err = konf.Unmarshal("", s); err != nil {
		return s, fmt.Errorf("unable to process config file: %s", err.Error())
	}

	if len(s.AccountPrimaryTag) == 0 {
		s.AccountPrimaryTag = append(s.AccountPrimaryTag, DEFAULT_ACCOUNT_PRIMARY_TAGS...)
	}

	s.setOverrides(override)

	// set our SSO names
	for k, v := range s.SSO {
		v.key = k
	}

	if _, ok := s.SSO[s.DefaultSSO]; !ok {
		// Select our SSO Provider
		if len(s.SSO) == 0 {
			return s, fmt.Errorf("no AWS SSO providers have been configured")
		} else if len(s.SSO) == 1 {
			// If we have only one SSO configured, always use that
			for name := range s.SSO {
				s.DefaultSSO = name
			}
		} else {
			// more than one provider? use that
			names := []string{}
			for sso := range s.SSO {
				names = append(names, sso)
			}
			if len(names) > 0 {
				return s, fmt.Errorf("invalid SSO name '%s'. Valid options: %s", s.DefaultSSO,
					strings.Join(names, ", "))
			} else {
				// couldn't find a valid provider
				return s, fmt.Errorf("please specify --sso, $AWS_SSO or set DefaultSSO in the config file")
			}
		}
	}

	s.SSO[s.DefaultSSO].Refresh(s)

	s.applyDeprecations()

	// ConfigProfilesUrlAction should track UrlAcition unless it is set
	if s.ConfigProfilesUrlAction == "" {
		s.ConfigProfilesUrlAction = s.UrlAction.GetConfigProfilesAction()
	}

	if err = s.Validate(); err != nil {
		return s, err
	}

	// load the cache
	if s.Cache, err = OpenCache(s.cacheFile, s); err != nil {
		log.Info("unable to open cache file", "error", err.Error())
	}

	return s, nil
}

func (s *Settings) Validate() error {
	// Does either action call `exec` without firefox containers?
	if s.UrlAction.IsContainer() != s.ConfigProfilesUrlAction.IsContainer() {
		if s.UrlAction == url.Exec || s.ConfigProfilesUrlAction == url.ConfigProfilesExec {
			return fmt.Errorf("must not select `exec` and a Firefox container option")
		}
	}

	return nil
}

// applyDeprecations migrates old config options to the new one and returns true
// if we made a change
func (s *Settings) applyDeprecations() bool {
	var change = false
	var err error

	// Upgrade ConfigUrlAction to ConfigProfilesUrlAction because we want to
	// deprecate ConfigUrlAction.
	if s.ConfigUrlAction != "" && s.ConfigProfilesUrlAction == "" {
		s.ConfigProfilesUrlAction, err = url.NewConfigProfilesAction(s.ConfigUrlAction)
		if err != nil {
			log.Warn("Invalid value for ConfigUrlAction", "value", s.ConfigUrlAction)
		}
		s.ConfigUrlAction = string(url.Undef) // disable old value so it is omitempty
		change = true
	}

	// Upgrade FirefoxOpenUrlInContainer to UrlAction = open-url-in-container
	if s.FirefoxOpenUrlInContainer {
		s.UrlAction = url.OpenUrlContainer
		s.FirefoxOpenUrlInContainer = false // disable old value so it is omitempty
		change = true
	}

	// ExpiresStr => Expires in v1.11.0
	// AccountIdStr => AccountIdPad v1.11.0
	// ARN => Arn v1.11.0
	if len(s.ListFields) > 0 {
		for i, v := range s.ListFields {
			switch v {
			case "ExpiresStr":
				s.ListFields[i] = "Expires"
			case "AccountIdStr":
				s.ListFields[i] = "AccountIdPad"
			case "ARN":
				s.ListFields[i] = "Arn"
			}
		}
	}

	// AccountIdStr .AccountId => .AccountIdPad in v1.11.0
	s.ProfileFormat = strings.ReplaceAll(s.ProfileFormat, "AccountIdStr .AccountId", ".AccountIdPad")

	return change
}

// Save overwrites the current config file with our settings (not recommended)
func (s *Settings) Save(configFile string, overwrite bool) error {
	var err error

	if _, err = os.Stat(configFile); !errors.Is(err, os.ErrNotExist) && !overwrite {
		return fmt.Errorf("refusing to overwrite %s", configFile)
	}

	var output bytes.Buffer
	w := bufio.NewWriter(&output)

	encoder := goyaml.NewEncoder(w, goyaml.Indent(4), goyaml.IndentSequence(true))
	if err = encoder.Encode(s); err != nil {
		return err
	}
	if err = encoder.Close(); err != nil {
		return err
	}
	w.Flush()
	fileBytes := output.Bytes()
	if len(fileBytes) == 0 {
		return fmt.Errorf("refusing to write 0 bytes to config.yaml")
	}

	configDir := fileutils.GetHomePath(filepath.Dir(configFile))
	configFile = filepath.Join(configDir, filepath.Base(configFile))
	if err = fileutils.EnsureDirExists(configFile); err != nil {
		return err
	}

	// need to make directory if not exist
	return os.WriteFile(configFile, fileBytes, 0600)
}

// configure our settings using the overrides
func (s *Settings) setOverrides(override OverrideSettings) {
	// Setup Logging
	if override.LogLevel != "" {
		s.LogLevel = override.LogLevel
	}

	err := log.SetLevelString(s.LogLevel)
	if err != nil {
		log.Fatal("Invalid log level", "level", s.LogLevel, "error", err.Error())
	}

	if override.LogLines {
		s.LogLines = true
	}
	log.SetReportCaller(s.LogLines)

	// Other overrides from CLI
	if override.Browser != "" {
		s.Browser = override.Browser
	}
	if override.DefaultSSO != "" {
		s.DefaultSSO = override.DefaultSSO
	}

	if override.Threads > 0 {
		s.Threads = override.Threads
	}
}

func (s *Settings) ConfigFile() string {
	return s.configFile
}

func (s *Settings) CreatedAt() int64 {
	f, err := os.Open(s.configFile)
	if err != nil {
		log.Fatal("Unable to open", "file", s.configFile, "error", err.Error())
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		log.Fatal("Unable to Stat()", "file", s.configFile, "error", err.Error())
	}
	return info.ModTime().Unix()
}

// GetSelectedSSO returns a valid SSOConfig based on user intput, configured
// value or our hardcoded 'Default' if it exists and name is empty String
func (s *Settings) GetSelectedSSO(name string) (*SSOConfig, error) {
	n, err := s.GetSelectedSSOName(name)
	if err != nil {
		return &SSOConfig{}, err
	}
	return s.SSO[n], nil
}

// GetSelectedSSOName returns the name of the selected SSO name where
// the input is the option passed in via the CLI (should be an empty string)
// if user did not specify a value on the CLI
func (s *Settings) GetSelectedSSOName(name string) (string, error) {
	if name != "" {
		if _, ok := s.SSO[name]; ok {
			return name, nil
		}

		return "", fmt.Errorf("'%s' is not a valid AWS SSO Instance", name)
	}

	if _, ok := s.SSO[s.DefaultSSO]; ok {
		return s.DefaultSSO, nil
	}

	if _, ok := s.SSO["Default"]; ok {
		return "Default", nil
	}
	return "", fmt.Errorf("no available AWS SSO Instance")
}

// Returns the Tag name => Environment variable name
func (s *Settings) GetEnvVarTags() map[string]string {
	ret := map[string]string{}
	for _, tag := range s.EnvVarTags {
		ret[tag] = fmt.Sprintf("AWS_SSO_TAG_%s", strings.ToUpper(tag))
	}
	return ret
}

type ProfileMap map[string]map[string]ProfileConfig

type ProfileConfig struct {
	Arn             string
	BinaryPath      string
	ConfigVariables map[string]interface{}
	DefaultRegion   string
	Open            string
	Profile         string
	Sso             string
}

// allow os.Executable call to be overridden for unit testing purposes
var getExecutable func() (string, error) = func() (string, error) {
	exec, err := os.Executable()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(exec, NIX_STORE_PREFIX) {
		log.Warn("Detected NIX. Using $PATH to find `aws-sso`. Override with `ConfigProfilesBinaryPath`")
		exec = "aws-sso"
	}
	return exec, nil
}

// GetAllProfiles returns a map of the ProfileConfig for each SSOConfig.
// takes the binary path to `open` URL with if set
func (s *Settings) GetAllProfiles() (*ProfileMap, error) {
	profiles := ProfileMap{}
	var err error

	binaryPath := s.ConfigProfilesBinaryPath
	if binaryPath == "" {
		if binaryPath, err = getExecutable(); err != nil {
			return &profiles, err
		}
	}

	// Find all the roles across all of the SSO instances
	for ssoName, sso := range s.Cache.SSO {
		for _, role := range sso.Roles.GetAllRoles() {
			profile, err := role.ProfileName(s)
			if err != nil {
				return &profiles, err
			}

			if _, ok := profiles[ssoName]; !ok {
				profiles[ssoName] = map[string]ProfileConfig{}
			}

			profiles[ssoName][role.Arn] = ProfileConfig{
				Arn:             role.Arn,
				BinaryPath:      binaryPath,
				ConfigVariables: s.ConfigVariables,
				DefaultRegion:   role.DefaultRegion,
				Profile:         profile,
				Sso:             ssoName,
			}
		}
	}

	return &profiles, nil
}

// GetAllProfiles returns a map of the ProfileConfig for each SSOConfig.
// takes the binary path to `open` URL with if set
func (s *Settings) GetSSOProfiles(ssoName string) (*ProfileMap, error) {
	profiles := ProfileMap{}
	var err error

	binaryPath := s.ConfigProfilesBinaryPath
	if binaryPath == "" {
		if binaryPath, err = getExecutable(); err != nil {
			return &profiles, err
		}
	}

	// Find all the roles across all of the SSO instances
	//	for ssoName, sso := range s.Cache.SSO {
	sso := s.Cache.GetSSOByName(ssoName)
	for _, role := range sso.Roles.GetAllRoles() {
		profile, err := role.ProfileName(s)
		if err != nil {
			return &profiles, err
		}

		if _, ok := profiles[ssoName]; !ok {
			profiles[ssoName] = map[string]ProfileConfig{}
		}

		profiles[ssoName][role.Arn] = ProfileConfig{
			Arn:             role.Arn,
			BinaryPath:      binaryPath,
			ConfigVariables: s.ConfigVariables,
			DefaultRegion:   role.DefaultRegion,
			Profile:         profile,
			Sso:             ssoName,
		}
	}
	// }

	return &profiles, nil
}

// UniqueCheck verifies that all of the profiles are unique
func (p *ProfileMap) UniqueCheck(s *Settings) error {
	profileUniqueCheck := map[string][]string{} // ProfileName() => Arn

	for ssoName, sso := range s.Cache.SSO {
		for _, role := range sso.Roles.GetAllRoles() {
			profile, err := role.ProfileName(s)
			if err != nil {
				return err
			}

			if match, duplicate := profileUniqueCheck[profile]; duplicate {
				return fmt.Errorf("duplicate profile name '%s' for:\n%s: %s\n%s: %s",
					profile, match[0], match[1], ssoName, role.Arn)
			}
			profileUniqueCheck[profile] = []string{ssoName, role.Arn}
		}
	}

	return nil
}

func (p *ProfileMap) IsDuplicate(newProfile string) bool {
	for _, roles := range *p {
		for _, config := range roles {
			if config.Profile == newProfile {
				return true
			}
		}
	}
	return false
}
