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
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type LoginCmd struct{}

func (cc *LoginCmd) Run(ctx *RunContext) error {
	doAuth(ctx)
	return nil
}

// checkAuth craetes a singleton AWSSO object and checks to see if
// we have a valid SSO authentication token.  If this is false, then
// we need to call doAuth()
func checkAuth(ctx *RunContext) bool {
	if AwsSSO == nil {
		s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
		if err != nil {
			log.Fatalf("%s", err.Error())
		}

		AwsSSO = sso.NewAWSSSO(s, &ctx.Store)
	}

	return AwsSSO.ValidAuthToken()
}

// doAuth creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) {
	if checkAuth(ctx) {
		// nothing to do here
		log.Infof("You are already logged in. :)")
		return
	}

	err := AwsSSO.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	if err = ctx.Settings.Cache.Expired(s); err != nil {
		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		log.Infof("Refreshing AWS SSO role cache for %s, please wait...", ssoName)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if err = ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName, ctx.Cli.Threads); err != nil {
			log.WithError(err).Fatalf("Unable to refresh cache")
		}
		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.WithError(err).Errorf("Unable to save cache")
		}

		// should we update our config??
		if !ctx.Cli.NoConfigCheck && ctx.Settings.AutoConfigCheck {
			if ctx.Settings.ConfigProfilesUrlAction != url.ConfigProfilesUndef {
				action, _ := url.NewAction(string(ctx.Settings.ConfigProfilesUrlAction))
				err := awsconfig.UpdateAwsConfig(ctx.Settings, action, "", true, false)
				if err != nil {
					log.Errorf("Unable to auto-update aws config file: %s", err.Error())
				}
			}
		}
	}
}
