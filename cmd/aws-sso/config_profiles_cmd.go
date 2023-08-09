package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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

	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	AWS_CONFIG_FILE = "~/.aws/config"
	CONFIG_TEMPLATE = `{{range $sso, $struct := . }}{{ range $arn, $profile := $struct }}
[profile {{ $profile.Profile }}]
credential_process = {{ $profile.BinaryPath }} -u {{ $profile.Open }} -S "{{ $profile.Sso }}" process --arn {{ $profile.Arn }}
{{ if len $profile.DefaultRegion }}region = {{ printf "%s\n" $profile.DefaultRegion }}{{ end -}}
{{ range $key, $value := $profile.ConfigVariables }}{{ $key }} = {{ $value }}
{{end}}{{end}}{{end}}`
)

type ConfigProfilesCmd struct {
	Diff  bool   `kong:"help='Print a diff of changes to the config file instead of modifying it',xor='action'"`
	Force bool   `kong:"help='Write a new config file without prompting'"`
	Open  string `kong:"help='Specify how to open URLs: [clip|exec|open|granted-containers|open-url-in-container]'"`
	Print bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
}

func (cc *ConfigProfilesCmd) Run(ctx *RunContext) error {
	var err error
	var action url.ConfigProfilesAction

	if ctx.Cli.ConfigProfiles.Open != "" {
		if action, err = url.NewConfigProfilesAction(ctx.Cli.ConfigProfiles.Open); err != nil {
			return err
		}
	} else {
		action = ctx.Settings.ConfigProfilesUrlAction
	}

	if action == url.ConfigProfilesUndef {
		return fmt.Errorf("Please specify --open [clip|exec|open|granted-containers|open-url-in-container]")
	}

	urlAction, _ := url.NewAction(string(action))

	// refresh our cache
	c := &CacheCmd{}
	if err = c.Run(ctx); err != nil {
		return err
	}

	profiles, err := ctx.Settings.GetAllProfiles(urlAction)
	if err != nil {
		return err
	}

	if err := profiles.UniqueCheck(ctx.Settings); err != nil {
		return err
	}

	f, err := utils.NewFileEdit(CONFIG_TEMPLATE, profiles)
	if err != nil {
		return err
	}

	if ctx.Cli.ConfigProfiles.Print {
		return f.Template.Execute(os.Stdout, profiles)
	}

	oldConfig := awsConfigFile()
	return f.UpdateConfig(ctx.Cli.ConfigProfiles.Diff, ctx.Cli.ConfigProfiles.Force, oldConfig)
}

// awsConfigFile returns the path the the users ~/.aws/config
func awsConfigFile() string {
	// did user set the value?
	path := os.Getenv("AWS_CONFIG_FILE")
	if path == "" {
		path = utils.GetHomePath(AWS_CONFIG_FILE)
	}
	log.Debugf("path = %s", path)
	return path
}
