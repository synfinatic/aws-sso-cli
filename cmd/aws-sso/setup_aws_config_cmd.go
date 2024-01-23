package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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

	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

const (
	CONFIG_TEMPLATE = `{{range $sso, $struct := . }}{{ range $arn, $profile := $struct }}
[profile {{ $profile.Profile }}]
credential_process = {{ $profile.BinaryPath }} -u {{ $profile.Open }} -S "{{ $profile.Sso }}" process --arn {{ $profile.Arn }}
{{ if len $profile.DefaultRegion }}region = {{ printf "%s\n" $profile.DefaultRegion }}{{ end -}}
{{ range $key, $value := $profile.ConfigVariables }}{{ $key }} = {{ $value }}
{{end}}{{end}}{{end}}`
)

type AwsConfigCmd struct {
	Diff      bool   `kong:"help='Print a diff of changes to the config file instead of modifying it',xor='action'"`
	Force     bool   `kong:"help='Write a new config file without prompting'"`
	Open      string `kong:"help='Specify how to open URLs: [clip|exec|open|granted-containers|open-url-in-container]'"`
	Print     bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
	AwsConfig string `kong:"help='Path to AWS config file',env='AWS_CONFIG_FILE',default='~/.aws/config'"`
}

func (cc *AwsConfigCmd) Run(ctx *RunContext) error {
	var err error
	var action url.ConfigProfilesAction

	awsConfig := ctx.Cli.Setup.AwsConfig

	if awsConfig.Open != "" {
		if action, err = url.NewConfigProfilesAction(awsConfig.Open); err != nil {
			return err
		}
	} else {
		action = ctx.Settings.ConfigProfilesUrlAction
	}

	if action == url.ConfigProfilesUndef {
		return fmt.Errorf("Please specify --open [clip|exec|open|granted-containers|open-url-in-container]")
	}

	urlAction, _ := url.NewAction(string(action))

	// always refresh our cache
	c := &CacheCmd{}
	if err = c.Run(ctx); err != nil {
		return err
	}

	if awsConfig.Print {
		return awsconfig.PrintAwsConfig(ctx.Settings, urlAction)
	}
	return awsconfig.UpdateAwsConfig(ctx.Settings, urlAction, awsConfig.AwsConfig,
		awsConfig.Diff, awsConfig.Force)
}
