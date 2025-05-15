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
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

type CacheCmd struct {
	NoConfigCheck bool `kong:"help='Disable automatic ~/.aws/config updates'"`
	Threads       int  `kong:"help='Override number of threads for talking to AWS',default=${DEFAULT_THREADS}"`
}

// AfterApply determines if SSO auth token is required
func (c CacheCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *CacheCmd) Run(ctx *RunContext) error {
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatal("unable to select SSO instance", "sso", ctx.Cli.SSO, "error", err.Error())
	}

	ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
	if err != nil {
		log.Fatal("unable to get name for SSO instance", "sso", ctx.Cli.SSO, "error", err.Error())
	}

	added, deleted, err := ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName, ctx.Cli.Cache.Threads)
	if err != nil {
		return fmt.Errorf("unable to refresh role cache: %s", err.Error())
	}
	ctx.Settings.Cache.PruneSSO(ctx.Settings)

	err = ctx.Settings.Cache.Save(true)
	if err != nil {
		return fmt.Errorf("unable to save role cache: %s", err.Error())
	}

	if added > 0 || deleted > 0 {
		log.Info("Updated cache", "added", added, "deleted", deleted)
		// should we update our config??
		if !ctx.Cli.Cache.NoConfigCheck && ctx.Settings.AutoConfigCheck {
			if ctx.Settings.ConfigProfilesUrlAction != url.ConfigProfilesUndef {
				err := awsconfig.UpdateAwsConfig(ssoName, ctx.Settings, "", true, false)
				if err != nil {
					log.Error("Unable to auto-update aws config file", "error", err.Error())
				}
			}
		}
	}

	return nil
}
