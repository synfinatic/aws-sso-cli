package main

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
	"fmt"
	"os"
	"text/template"

	log "github.com/sirupsen/logrus"
)

const (
	//	CONFIG_PREFIX   = "# BEGIN_AWS_SSO_CLI"
	//	CONFIG_SUFFIX   = "# END_AWS_SSO_CLI"
	CONFIG_TEMPLATE = `
# BEGIN_AWS_SSO_CLI
{{ range . }}
[profile {{ .Profile }}]
credential_process = {{ .BinaryPath }} -u open -S "{{ .Sso }}" process --arn {{ .Arn }}
output={{ .Output }}
{{end}}
# END_AWS_SSO_CLI
`
)

type ProfileConfig struct {
	Sso        string
	Arn        string
	Profile    string
	Output     string
	BinaryPath string
}

type ConfigCmd struct {
	Print  bool   `kong:"help='Print profile entries instead of modifying config file'"`
	Output string `kong:"help='Output format [json|yaml|yaml-stream|text|table]',default='json',enum='json,yaml,yaml-stream,text,table'"`
}

func (cc *ConfigCmd) Run(ctx *RunContext) error {
	set := ctx.Settings
	binaryPath, _ := os.Executable()

	// Find all the roles across all of the SSO instances
	profiles := []ProfileConfig{}
	for ssoName, s := range set.Cache.SSO {
		for _, role := range s.Roles.GetAllRoles() {
			profile, err := role.ProfileName(ctx.Settings)
			if err != nil {
				log.Errorf("Unable to generate profile name for %s: %s", role.Arn, err.Error())
			}
			profiles = append(profiles, ProfileConfig{
				Sso:        ssoName,
				Arn:        role.Arn,
				Profile:    profile,
				Output:     ctx.Cli.Config.Output,
				BinaryPath: binaryPath,
			})
		}
	}

	templ, err := template.New("profile").Parse(CONFIG_TEMPLATE)
	if err != nil {
		return err
	}
	if ctx.Cli.Config.Print {
		if err := templ.Execute(os.Stdout, profiles); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Writing to ~/.aws/config is not yet supported")
	}

	return nil
}
