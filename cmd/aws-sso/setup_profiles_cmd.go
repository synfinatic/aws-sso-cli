package main

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
	"fmt"

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
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *SetupProfilesCmd) Run(ctx *RunContext) error {
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatal("unable to select SSO instance", "sso", ctx.Cli.SSO, "error", err.Error())
	}

	ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
	if err != nil {
		log.Fatal("unable to select SSO instance", "sso", ctx.Cli.SSO, "error", err.Error())
	}

	if err = ctx.Settings.Cache.Expired(s); err != nil {
		c := &CacheCmd{}
		if err = c.Run(ctx); err != nil {
			return fmt.Errorf("unable to refresh role cache: %s", err.Error())
		}
	}

	if ctx.Cli.Setup.Profiles.Print {
		return awsconfig.PrintAwsConfig(ssoName, ctx.Settings)
	}
	return awsconfig.UpdateAwsConfig(ssoName, ctx.Settings, ctx.Cli.Setup.Profiles.AwsConfig,
		ctx.Cli.Setup.Profiles.Diff, ctx.Cli.Setup.Profiles.Force)
}
