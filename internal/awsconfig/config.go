package awsconfig

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
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	AWS_CONFIG_FILE = "~/.aws/config"
	CONFIG_TEMPLATE = `{{range $sso, $struct := . }}{{ range $arn, $profile := $struct }}
[profile {{ $profile.Profile }}]
credential_process = {{ $profile.BinaryPath }} -S "{{ $profile.Sso }}" process --arn {{ $profile.Arn }}
{{ if len $profile.DefaultRegion }}region = {{ printf "%s\n" $profile.DefaultRegion }}{{ end -}}
{{ range $key, $value := $profile.ConfigVariables }}{{ $key }} = {{ $value }}
{{end}}{{end}}{{end}}`
)

// AwsConfigFile determines the correct location for the AWS config file
func AwsConfigFile(cfile string) string {
	if cfile != "" {
		return utils.GetHomePath(cfile)
	} else if p, ok := os.LookupEnv("AWS_CONFIG_FILE"); ok {
		return utils.GetHomePath(p)
	}
	return utils.GetHomePath(AWS_CONFIG_FILE)
}

var stdout = os.Stdout

// PrintAwsConfig just prints what our new AWS config file block would look like
func PrintAwsConfig(ssoName string, s *sso.Settings) error {
	profiles, err := getProfileMap(ssoName, s)
	if err != nil {
		return err
	}

	f, err := utils.NewFileEdit(CONFIG_TEMPLATE, s.DefaultSSO, profiles)
	if err != nil {
		return err
	}

	return f.Template.Execute(stdout, profiles)
}

// UpdateAwsConfig updates our AWS config file, optionally presenting a diff for
// review or possibly making the change without prompting
func UpdateAwsConfig(ssoName string, s *sso.Settings, cfile string, diff, force bool) error {
	profiles, err := getProfileMap(ssoName, s)
	if err != nil {
		return err
	}

	f, err := utils.NewFileEdit(CONFIG_TEMPLATE, s.DefaultSSO, profiles)
	if err != nil {
		return err
	}

	oldConfig := AwsConfigFile(cfile)
	_, _, err = f.UpdateConfig(diff, force, oldConfig)
	return err
}

// getProfileMap returns our validated sso.ProfileMap
func getProfileMap(ssoName string, s *sso.Settings) (*sso.ProfileMap, error) {
	profiles, err := s.GetSSOProfiles(ssoName)
	if err != nil {
		return profiles, err
	}

	if err := profiles.UniqueCheck(s); err != nil {
		return profiles, err
	}

	return profiles, nil
}
