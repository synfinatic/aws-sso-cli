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
	"fmt"
	"os"
	"strings"

	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
)

const (
	NIX_STORE_PREFIX = "/nix/store/"
)

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

// resolvedBinaryPath returns the binary path to use for profile generation.
// It prefers ConfigProfilesBinaryPath if set, otherwise falls back to the
// current executable path.
func (s *Settings) resolvedBinaryPath() (string, error) {
	if s.ConfigProfilesBinaryPath != "" {
		return s.ConfigProfilesBinaryPath, nil
	}
	return getExecutable()
}

// buildProfilesForSSO populates profiles with a ProfileConfig for every role
// in the given SSOCache instance.  profiles is a map type (reference) so
// mutations are visible to the caller.
func (s *Settings) buildProfilesForSSO(profiles ProfileMap, ssoName string, sso *ssocache.SSOCache, binaryPath string) error {
	for _, role := range sso.Roles.GetAllRoles() {
		profile, err := role.ProfileName(s)
		if err != nil {
			return err
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
	return nil
}

// GetAllProfiles returns a ProfileMap for all SSO instances and their roles.
func (s *Settings) GetAllProfiles() (*ProfileMap, error) {
	profiles := ProfileMap{}

	binaryPath, err := s.resolvedBinaryPath()
	if err != nil {
		return &profiles, err
	}

	for ssoName, sso := range s.Cache.SSO {
		if err := s.buildProfilesForSSO(profiles, ssoName, sso, binaryPath); err != nil {
			return &profiles, err
		}
	}

	return &profiles, nil
}

// GetSSOProfiles returns a ProfileMap for the roles in a single SSO instance.
func (s *Settings) GetSSOProfiles(ssoName string) (*ProfileMap, error) {
	profiles := ProfileMap{}

	binaryPath, err := s.resolvedBinaryPath()
	if err != nil {
		return &profiles, err
	}

	sso := s.Cache.GetSSOByName(ssoName)
	if err := s.buildProfilesForSSO(profiles, ssoName, sso, binaryPath); err != nil {
		return &profiles, err
	}

	return &profiles, nil
}

// UniqueCheck verifies that all of the profiles are unique.
// Only checks profiles that are actually in the ProfileMap rather than
// iterating over all cached SSO instances, which could produce false
// duplicates when the ProfileFormat includes {{ .SSO }}.
func (p *ProfileMap) UniqueCheck(s *Settings) error {
	profileUniqueCheck := map[string][]string{} // ProfileName() => Arn

	for ssoName, roles := range *p {
		for arn, config := range roles {
			profile := config.Profile

			if match, duplicate := profileUniqueCheck[profile]; duplicate {
				return fmt.Errorf("duplicate profile name '%s' for:\n%s: %s\n%s: %s",
					profile, match[0], match[1], ssoName, arn)
			}
			profileUniqueCheck[profile] = []string{ssoName, arn}
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
