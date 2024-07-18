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
	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
)

const (
	CONFIG_TEMPLATE = `{{range $sso, $struct := . }}{{ range $arn, $profile := $struct }}
[profile {{ $profile.Profile }}]
credential_process = {{ $profile.BinaryPath }} -u {{ $profile.Open }} -S "{{ $profile.Sso }}" process --arn {{ $profile.Arn }}
{{ if len $profile.DefaultRegion }}region = {{ printf "%s\n" $profile.DefaultRegion }}{{ end -}}
{{ range $key, $value := $profile.ConfigVariables }}{{ $key }} = {{ $value }}
{{end}}{{end}}{{end}}`
)

type SetupProfilesCmd struct {
	Diff      bool   `kong:"help='Print a diff of changes to the config file instead of modifying it',xor='action'"`
	Force     bool   `kong:"help='Write a new config file without prompting'"`
	Print     bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
	AwsConfig string `kong:"help='Path to AWS config file',env='AWS_CONFIG_FILE',default='~/.aws/config'"`
}

// AfterApply determines if SSO auth token is required
func (s SetupProfilesCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *SetupProfilesCmd) Run(ctx *RunContext) error {
	var err error

	// always refresh our cache
	c := &CacheCmd{}
	if err = c.Run(ctx); err != nil {
		return err
	}

	if ctx.Cli.Setup.Profiles.Print {
		return awsconfig.PrintAwsConfig(ctx.Settings)
	}
	return awsconfig.UpdateAwsConfig(ctx.Settings, ctx.Cli.Setup.Profiles.AwsConfig,
		ctx.Cli.Setup.Profiles.Diff, ctx.Cli.Setup.Profiles.Force)
}
